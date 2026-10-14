#!/usr/bin/env python3
"""
fmtprobe.py — structural metadata extractor for Huntress CTF metadata-forensics.

Reads the *real bytes* of a file and reports the exact structural fields the
Game Master asks about, each already formatted to the grader's required syntax.

Field taxonomy (observed across days 1-13):

  generic (any file)
    size                 base-10 byte count
    md5 / sha1 / sha256  hex digest (lowercase)
    first16              first 16 bytes as 32 lowercase hex chars (no 0x/spaces)

  jpeg.sof_dimensions_pixels      "WxH" from the Start-Of-Frame marker
  png.ihdr_dimensions_pixels      "WxH" from the IHDR chunk
  pdf.header_version              "X.Y" from the literal %PDF-X.Y header
  text.utf8_bom_present           "true"/"false" (leading EF BB BF)
  zip.eocd_total_entries          integer from the End-Of-Central-Directory record
  zip.central_directory_member_names   compact JSON array, central-directory order
  pe.coff_machine_u16_hex         "0xNNNN" COFF Machine (u16, 4 hex digits)
  pe.address_of_entry_point_rva_hex    "0xN..." AddressOfEntryPoint RVA (minimal)
  pe.version_original_filename    OriginalFilename string from VS_VERSION_INFO
  dotnet.mvid_guid                Module Version ID, canonical 8-4-4-4-12 lowercase
  msi.product_code_guid           ProductCode GUID from the MSI Property table

Usage:
    fmtprobe.py <file>                 auto-detect; print every field it can
    fmtprobe.py <file> --field NAME    print just that field's grader-ready value
    fmtprobe.py <file> --json          machine-readable {field: value}

Designed to be run with `python3 -I` on untrusted downloaded bytes.
"""
import sys, os, re, struct, hashlib, json, subprocess, argparse, uuid


# ---------------------------------------------------------------- generic ----
def f_size(b):   return str(len(b))
def f_md5(b):    return hashlib.md5(b).hexdigest()
def f_sha1(b):   return hashlib.sha1(b).hexdigest()
def f_sha256(b): return hashlib.sha256(b).hexdigest()
def f_first16(b):return b[:16].hex()


# ------------------------------------------------------------------- jpeg ----
_SOF = {0xC0,0xC1,0xC2,0xC3,0xC5,0xC6,0xC7,0xC9,0xCA,0xCB,0xCD,0xCE,0xCF}

def jpeg_sof_dimensions(b):
    if b[:2] != b"\xff\xd8":
        return None
    i = 2
    n = len(b)
    while i < n - 1:
        if b[i] != 0xFF:
            i += 1; continue
        m = b[i+1]
        if m == 0xD8 or m == 0xD9 or 0xD0 <= m <= 0xD7 or m == 0xFF:
            i += 2; continue
        if i+4 > n: break
        seglen = struct.unpack(">H", b[i+2:i+4])[0]
        if m in _SOF:
            h = struct.unpack(">H", b[i+5:i+7])[0]
            w = struct.unpack(">H", b[i+7:i+9])[0]
            return f"{w}x{h}"
        i += 2 + seglen
    return None


# -------------------------------------------------------------------- png ----
def png_ihdr_dimensions(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    # first chunk must be IHDR: len(4) type(4) data...
    if b[12:16] != b"IHDR":
        return None
    w = struct.unpack(">I", b[16:20])[0]
    h = struct.unpack(">I", b[20:24])[0]
    return f"{w}x{h}"


# -------------------------------------------------------------------- pdf ----
def pdf_header_version(b):
    # Header may be preceded by a few junk bytes per spec; search a small window.
    head = b[:1024]
    idx = head.find(b"%PDF-")
    if idx < 0:
        return None
    ver = head[idx+5:idx+12].split(b"\r")[0].split(b"\n")[0].split(b"%")[0]
    ver = ver.decode("latin-1").strip()
    # keep only X.Y digits/dot
    out = ""
    for c in ver:
        if c.isdigit() or c == ".":
            out += c
        else:
            break
    return out or None


# ------------------------------------------------------------------- text ----
def text_utf8_bom_present(b):
    return "true" if b[:3] == b"\xef\xbb\xbf" else "false"


# -------------------------------------------------------------------- zip ----
def _zip_eocd_offset(b):
    sig = b"PK\x05\x06"
    # EOCD is near the end; comment <= 65535. Scan backwards.
    start = max(0, len(b) - (22 + 65535))
    idx = b.rfind(sig, start)
    return idx

def zip_eocd_total_entries(b):
    idx = _zip_eocd_offset(b)
    if idx < 0:
        return None
    total = struct.unpack("<H", b[idx+10:idx+12])[0]
    cd_off = struct.unpack("<I", b[idx+16:idx+20])[0]
    # ZIP64 fallback when the classic fields are saturated.
    if total == 0xFFFF or cd_off == 0xFFFFFFFF:
        z = b.rfind(b"PK\x06\x06")
        if z >= 0:
            total = struct.unpack("<Q", b[z+32:z+40])[0]
    return str(total)

def zip_central_directory_member_names(b):
    idx = _zip_eocd_offset(b)
    if idx < 0:
        return None
    cd_off = struct.unpack("<I", b[idx+16:idx+20])[0]
    cd_size = struct.unpack("<I", b[idx+12:idx+16])[0]
    if cd_off == 0xFFFFFFFF:  # ZIP64
        z = b.rfind(b"PK\x06\x06")
        if z >= 0:
            cd_off = struct.unpack("<Q", b[z+48:z+56])[0]
    names = []
    p = cd_off
    while p + 46 <= len(b) and b[p:p+4] == b"PK\x01\x02":
        nlen = struct.unpack("<H", b[p+28:p+30])[0]
        elen = struct.unpack("<H", b[p+30:p+32])[0]
        clen = struct.unpack("<H", b[p+32:p+34])[0]
        name = b[p+46:p+46+nlen].decode("utf-8", "surrogateescape")
        names.append(name)
        p += 46 + nlen + elen + clen
    return json.dumps(names, ensure_ascii=False, separators=(",", ":"))


# --------------------------------------------------------------------- pe ----
def _pe_offsets(b):
    if b[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack("<I", b[0x3C:0x40])[0]
    if b[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return None
    return e_lfanew

def pe_coff_machine_u16_hex(b):
    o = _pe_offsets(b)
    if o is None:
        return None
    machine = struct.unpack("<H", b[o+4:o+6])[0]
    return f"0x{machine:04x}"

def pe_address_of_entry_point_rva_hex(b):
    o = _pe_offsets(b)
    if o is None:
        return None
    opt = o + 24  # after 4-byte sig + 20-byte COFF header
    aoep = struct.unpack("<I", b[opt+16:opt+20])[0]
    return f"0x{aoep:x}"

def pe_version_original_filename(path):
    # VS_VERSION_INFO parsing is fiddly; exiftool reads it reliably.
    try:
        out = subprocess.run(
            ["exiftool", "-s3", "-OriginalFileName", path],
            capture_output=True, text=True, timeout=30).stdout.strip()
        return out or "none"
    except Exception:
        return None


# ------------------------------------------------------------------ dotnet ----
def dotnet_mvid_guid(path):
    try:
        import dnfile
    except ImportError:
        return None
    try:
        pe = dnfile.dnPE(path, clr_lazy_load=True)
        mod = pe.net.mdtables.Module
        raw = mod.rows[0].Mvid
        data = getattr(raw, "value", raw)
        if isinstance(data, uuid.UUID):
            return str(data)
        if isinstance(data, (bytes, bytearray)) and len(data) == 16:
            return str(uuid.UUID(bytes_le=bytes(data)))
    except Exception:
        return None
    return None


# --------------------------------------------------------------------- msi ----
def msi_product_code_guid(path):
    try:
        out = subprocess.run(
            ["msiinfo", "export", path, "Property"],
            capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == "ProductCode":
            return parts[1].strip()
    return None


# --------------------------------------------------------------------- lnk ----
def lnk_target_path_windows(path):
    """Target path of a Windows .lnk shell link.

    Canonical source is LinkInfo: LocalBasePath + CommonPathSuffix. Falls back
    to the relative-path / environment-variable target blocks when LinkInfo has
    no local path (e.g. a network or environment-based target).
    """
    try:
        import LnkParse3
    except ImportError:
        return None
    try:
        with open(path, "rb") as f:
            d = LnkParse3.lnk_file(f).get_json()
    except Exception:
        return None
    li = d.get("link_info") or {}
    base = li.get("local_base_path") or li.get("local_base_path_unicode") or ""
    suffix = li.get("common_path_suffix") or li.get("common_path_suffix_unicode") or ""
    full = (base + suffix).strip()
    if full:
        return full
    # network share target
    net = (li.get("common_network_relative_link") or {}).get("net_name")
    if net:
        return (net + suffix).strip()
    # fallbacks held under the extra data blocks
    data = d.get("data") or {}
    for k, v in data.items():
        if isinstance(v, str) and v.strip() and \
           ("environment" in k.lower() or "relative_path" in k.lower()):
            return v.strip()
    return "none"


# -------------------------------------------------------------- dispatch ----
BYTE_FIELDS = {
    "size": f_size, "md5": f_md5, "sha1": f_sha1, "sha256": f_sha256,
    "first16": f_first16,
    "jpeg.sof_dimensions_pixels": jpeg_sof_dimensions,
    "png.ihdr_dimensions_pixels": png_ihdr_dimensions,
    "pdf.header_version": pdf_header_version,
    "text.utf8_bom_present": text_utf8_bom_present,
    "zip.eocd_total_entries": zip_eocd_total_entries,
    "zip.central_directory_member_names": zip_central_directory_member_names,
    "pe.coff_machine_u16_hex": pe_coff_machine_u16_hex,
    "pe.address_of_entry_point_rva_hex": pe_address_of_entry_point_rva_hex,
}
PATH_FIELDS = {
    "pe.version_original_filename": pe_version_original_filename,
    "dotnet.mvid_guid": dotnet_mvid_guid,
    "msi.product_code_guid": msi_product_code_guid,
    "lnk.target_path_windows": lnk_target_path_windows,
}
# fields that are only meaningful for a matching magic; used for auto mode
MAGIC_FIELDS = {
    "jpeg.sof_dimensions_pixels": lambda b: b[:2] == b"\xff\xd8",
    "png.ihdr_dimensions_pixels": lambda b: b[:8] == b"\x89PNG\r\n\x1a\n",
    "pdf.header_version":         lambda b: b[:1024].find(b"%PDF-") >= 0,
    "zip.eocd_total_entries":     lambda b: b[:4] == b"PK\x03\x04" or b.rfind(b"PK\x05\x06") >= 0,
    "zip.central_directory_member_names": lambda b: b.rfind(b"PK\x05\x06") >= 0,
    "pe.coff_machine_u16_hex":    lambda b: b[:2] == b"MZ",
    "pe.address_of_entry_point_rva_hex": lambda b: b[:2] == b"MZ",
}


def exiftool_lookup(path, field):
    """Best-effort fallback for a field we have no dedicated parser for.

    Maps a dotted field name (e.g. 'tiff.image_description') to an exiftool
    tag by matching the last component's words against tag names, and returns
    the tag's value. Enables day-N fields the toolkit has not been taught yet,
    as long as exiftool exposes them. Returns (value, tag) or (None, None).
    """
    comp = field.split(".")[-1]
    # drop type/width hints that aren't part of the tag name
    comp = re.sub(r"_(u\d+|hex|pixels|bytes|guid|rva|string|text)$", "", comp)
    want = comp.replace("_", "").lower()
    try:
        out = subprocess.run(["exiftool", "-j", "-a", "-G1", "-s", path],
                             capture_output=True, text=True, timeout=30).stdout
        tags = json.loads(out)[0]
    except Exception:
        return None, None
    # exact-ish match first, then substring
    best = None
    for k, v in tags.items():
        name = k.split(":")[-1].lower()
        if name == want:
            return str(v), k
        if best is None and (want in name or name in want):
            best = (str(v), k)
    return best if best else (None, None)


def compute(path, field, allow_exiftool_fallback=True):
    if field in PATH_FIELDS:
        return PATH_FIELDS[field](path)
    if field in BYTE_FIELDS:
        with open(path, "rb") as fh:
            return BYTE_FIELDS[field](fh.read())
    if allow_exiftool_fallback:
        val, tag = exiftool_lookup(path, field)
        if val is not None:
            sys.stderr.write(f"fmtprobe: '{field}' via exiftool tag {tag} "
                             f"(verify format)\n")
            return val
    return None


def auto(path):
    with open(path, "rb") as fh:
        b = fh.read()
    res = {}
    for name in ("size", "md5", "sha1", "sha256", "first16"):
        res[name] = BYTE_FIELDS[name](b)
    for name, test in MAGIC_FIELDS.items():
        try:
            if test(b):
                v = BYTE_FIELDS[name](b)
                if v is not None:
                    res[name] = v
        except Exception:
            pass
    # text BOM only relevant for text-ish files; report always (cheap, unambiguous)
    res["text.utf8_bom_present"] = text_utf8_bom_present(b)
    # path-based, magic-gated
    if b[:2] == b"MZ":
        of = pe_version_original_filename(path)
        if of: res["pe.version_original_filename"] = of
        mv = dotnet_mvid_guid(path)
        if mv: res["dotnet.mvid_guid"] = mv
    if b[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":  # OLE2 (MSI)
        pc = msi_product_code_guid(path)
        if pc: res["msi.product_code_guid"] = pc
    if b[:4] == b"\x4c\x00\x00\x00" and b[4:20] == \
            b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46":  # LNK
        tp = lnk_target_path_windows(path)
        if tp: res["lnk.target_path_windows"] = tp
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--field")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not os.path.isfile(a.file):
        raise SystemExit(f"fmtprobe: not a file: {a.file}")
    if a.field:
        v = compute(a.file, a.field)
        print(v if v is not None else "none")
        return
    res = auto(a.file)
    if a.json:
        print(json.dumps(res, ensure_ascii=False))
    else:
        for k, v in res.items():
            print(f"{k} = {v}")


if __name__ == "__main__":
    main()
