"""
fmtprobe_ext.py — extended structural field parsers (Huntress days 16+).

Each function takes a filesystem path and returns the grader-ready string (or
the literal "none" when the field is absent, or None when the file is not of
the expected type). fmtprobe.py imports EXT_PATH_FIELDS and merges it into its
dispatch table; solve.py then routes questions here automatically.

Kept separate from fmtprobe.py's hand-verified core so the growing catalogue of
one-off container formats stays readable.
"""
import struct, json, hashlib, subprocess, base64, re, zipfile, email


# ---- email (day 16) --------------------------------------------------------
def email_message_id(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f)
    for k in ("Message-ID", "Message-Id", "Message-id"):
        v = msg.get(k)
        if v:
            return v.strip()
    return "none"


# ---- media via ffprobe (days 17, 18) --------------------------------------
def _ffprobe(path, stream, entry):
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "error", "-select_streams", f"{stream}:0",
             "-show_entries", f"stream={entry}", "-of", "default=nk=1:nw=1", path],
            capture_output=True, text=True, timeout=60).stdout.strip()
        return out.splitlines()[0] if out else None
    except Exception:
        return None

def media_primary_audio_codec_name(path):
    return _ffprobe(path, "a", "codec_name") or "none"

def media_primary_video_dimensions(path):
    w = _ffprobe(path, "v", "width")
    h = _ffprobe(path, "v", "height")
    return f"{w}x{h}" if w and h else "none"


# ---- ELF (day 19) ----------------------------------------------------------
def elf_e_machine_u16_hex(path):
    with open(path, "rb") as f:
        b = f.read(20)
    if b[:4] != b"\x7fELF":
        return None
    le = b[5] == 1
    em = struct.unpack("<H" if le else ">H", b[18:20])[0]
    return f"0x{em:04x}"


# ---- Mach-O (day 20) -------------------------------------------------------
def macho_cpu_type_set(path):
    with open(path, "rb") as f:
        b = f.read()
    m = b[:4]
    types = []
    if m == b"\xca\xfe\xba\xbe":            # FAT_MAGIC (counts big-endian)
        n = struct.unpack(">I", b[4:8])[0]
        for i in range(n):                  # fat_arch = 20 bytes
            types.append(struct.unpack(">I", b[8 + i*20: 12 + i*20])[0])
    elif m == b"\xca\xfe\xba\xbf":          # FAT_MAGIC_64
        n = struct.unpack(">I", b[4:8])[0]
        for i in range(n):                  # fat_arch_64 = 32 bytes
            types.append(struct.unpack(">I", b[8 + i*32: 12 + i*32])[0])
    elif m in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):   # thin, little-endian
        types.append(struct.unpack("<I", b[4:8])[0])
    elif m in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):   # thin, big-endian
        types.append(struct.unpack(">I", b[4:8])[0])
    else:
        return None
    # grader expects lowercase 0x-prefixed hex cputype values, sorted ascending
    return json.dumps(sorted(f"0x{t:08x}" for t in types), separators=(",", ":"))


# ---- JAR (day 22) ----------------------------------------------------------
def jar_main_class(path):
    try:
        with zipfile.ZipFile(path) as z:
            mf = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
    except Exception:
        return None
    unfolded = []
    for ln in mf.split("\n"):
        ln = ln.rstrip("\r")
        if ln[:1] == " " and unfolded:
            unfolded[-1] += ln[1:]
        else:
            unfolded.append(ln)
    for ln in unfolded:
        if ln.lower().startswith("main-class:"):
            return ln.split(":", 1)[1].strip()
    return "none"


# ---- SQLite (day 23) -------------------------------------------------------
def sqlite_page_size_bytes(path):
    with open(path, "rb") as f:
        b = f.read(18)
    if b[:16] != b"SQLite format 3\x00":
        return None
    ps = struct.unpack(">H", b[16:18])[0]
    return str(65536 if ps == 1 else ps)


# ---- disk / partition table (day 28) ---------------------------------------
def disk_partition_start_lba_sequence(path):
    with open(path, "rb") as f:
        b = f.read()
    if len(b) < 512:
        return None
    mbr_types = [b[446 + i*16 + 4] for i in range(4)]
    lbas = []
    if 0xEE in mbr_types and b[512:520] == b"EFI PART":   # GPT
        hdr = b[512:1024]
        part_lba = struct.unpack("<Q", hdr[72:80])[0]
        num = struct.unpack("<I", hdr[80:84])[0]
        esize = struct.unpack("<I", hdr[84:88])[0]
        base = part_lba * 512
        for i in range(num):
            e = b[base + i*esize: base + i*esize + esize]
            if len(e) < 56 or e[0:16] == b"\x00" * 16:
                continue
            lbas.append(struct.unpack("<Q", e[32:40])[0])
    else:                                                  # classic MBR
        for i in range(4):
            e = b[446 + i*16: 446 + i*16 + 16]
            if e[4] == 0:
                continue
            lbas.append(struct.unpack("<I", e[8:12])[0])
    return json.dumps(lbas, separators=(",", ":"))


# ---- X.509 (day 29) --------------------------------------------------------
def x509_sha256_fingerprint(path):
    with open(path, "rb") as f:
        data = f.read()
    if b"-----BEGIN" in data:
        m = re.search(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
                      data, re.S)
        if not m:
            return None
        der = base64.b64decode(b"".join(m.group(1).split()))
    else:
        der = data   # already DER
    return hashlib.sha256(der).hexdigest()


# ---- OOXML external relationships (day 15) ---------------------------------
def ooxml_external_relationship_targets(path):
    import xml.etree.ElementTree as ET
    targets = []
    try:
        with zipfile.ZipFile(path) as z:
            for n in sorted(x for x in z.namelist() if x.endswith(".rels")):
                root = ET.fromstring(z.read(n))
                for rel in root:
                    if rel.get("TargetMode") == "External":
                        targets.append(rel.get("Target"))
    except Exception:
        return None
    return json.dumps(sorted(targets), separators=(",", ":"))   # ascending order


# ---- APK binary AndroidManifest.xml (day 21) -------------------------------
def _axml_strings(data, off):
    (_t, _h, _c, scount, _sty, flags, strstart, _stys) = \
        struct.unpack("<HHIIIIII", data[off:off + 28])
    utf8 = bool(flags & 0x100)
    offs = struct.unpack("<%dI" % scount, data[off + 28: off + 28 + 4 * scount])
    base = off + strstart
    out = []
    for o in offs:
        q = base + o
        if utf8:
            n = data[q]; q += 1
            if n & 0x80: q += 1                      # skip 2nd char-len byte
            m = data[q]; q += 1
            if m & 0x80:
                m = ((m & 0x7f) << 8) | data[q]; q += 1
            out.append(data[q:q + m].decode("utf-8", "replace"))
        else:
            n = struct.unpack("<H", data[q:q + 2])[0]; q += 2
            if n & 0x8000:
                n = ((n & 0x7fff) << 16) | struct.unpack("<H", data[q:q + 2])[0]; q += 2
            out.append(data[q:q + n * 2].decode("utf-16-le", "replace"))
    return out

def apk_package_name(path):
    try:
        with zipfile.ZipFile(path) as z:
            data = z.read("AndroidManifest.xml")
    except Exception:
        return None
    if data[:4] != b"\x03\x00\x08\x00":
        return None
    strings, off, total = None, 8, len(data)
    while off + 8 <= total:
        ctype = struct.unpack("<H", data[off:off + 2])[0]
        csize = struct.unpack("<I", data[off + 4:off + 8])[0]
        if csize <= 0:
            break
        if ctype == 0x0001 and strings is None:
            strings = _axml_strings(data, off)
        elif ctype == 0x0102 and strings is not None:      # START_TAG
            name_ref = struct.unpack("<I", data[off + 0x14:off + 0x18])[0]
            tag = strings[name_ref] if name_ref < len(strings) else ""
            if tag == "manifest":
                acount = struct.unpack("<H", data[off + 0x1C:off + 0x1E])[0]
                ab = off + 0x24
                for i in range(acount):
                    a = ab + i * 20
                    aname = struct.unpack("<I", data[a + 4:a + 8])[0]
                    raw = struct.unpack("<I", data[a + 8:a + 12])[0]
                    dtype = data[a + 15]
                    ddata = struct.unpack("<I", data[a + 16:a + 20])[0]
                    if aname < len(strings) and strings[aname] == "package":
                        if raw != 0xFFFFFFFF and raw < len(strings):
                            return strings[raw]
                        if dtype == 0x03 and ddata < len(strings):
                            return strings[ddata]
                return "none"
        off += csize
    return "none"


# ---- Windows Prefetch (day 26) ---------------------------------------------
def prefetch_executable_name(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:3] == b"MAM":                       # Win10/11 MAM-compressed
        try:
            from dissect.util.compression import lzxpress_huffman
            dec = lzxpress_huffman.decompress(raw[8:])
        except Exception:
            return None
    else:
        dec = raw
    if dec[4:8] != b"SCCA":
        return None
    # executable name: 60 UTF-16LE chars at offset 0x10, null-terminated
    name = dec[0x10:0x10 + 120].decode("utf-16-le", "replace").split("\x00")[0]
    return name or "none"


# ---- pcap / pcapng (day 27) ------------------------------------------------
def pcap_packet_count(path):
    with open(path, "rb") as f:
        b = f.read()
    if len(b) < 24:
        return None
    magic = b[:4]
    classic = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
               b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    if magic in classic:                       # classic pcap
        end = classic[magic]
        off, n = 24, 0
        while off + 16 <= len(b):
            incl = struct.unpack(end + "I", b[off + 8:off + 12])[0]
            off += 16 + incl
            n += 1
        return str(n)
    if magic == b"\x0a\x0d\x0d\x0a":           # pcapng
        end = "<" if b[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
        off, n = 0, 0
        while off + 12 <= len(b):
            btype = struct.unpack(end + "I", b[off:off + 4])[0]
            blen = struct.unpack(end + "I", b[off + 4:off + 8])[0]
            if blen < 12:
                break
            if btype in (0x00000002, 0x00000003, 0x00000006):  # (obsolete) packet, SPB, EPB
                n += 1
            off += blen
        return str(n)
    return None


# ---- EVTX (day 24) ---------------------------------------------------------
def evtx_record_count(path):
    with open(path, "rb") as f:
        hdr = f.read(0x20)
    if hdr[:8] != b"ElfFile\x00":
        return None
    next_id = struct.unpack("<Q", hdr[0x18:0x20])[0]   # NextRecordIdentifier
    return str(max(0, next_id - 1))


# ---- Windows registry hive (day 25) ----------------------------------------
def registry_hive_root_name(path):
    with open(path, "rb") as f:
        b = f.read()
    if b[:4] != b"regf":
        return None
    root_off = struct.unpack("<I", b[0x24:0x28])[0]
    nk = 0x1000 + root_off + 4            # +4 skips the cell size field
    if b[nk:nk + 2] != b"nk":
        return None
    flags = struct.unpack("<H", b[nk + 2:nk + 4])[0]
    nlen = struct.unpack("<H", b[nk + 0x48:nk + 0x4a])[0]
    name = b[nk + 0x4c: nk + 0x4c + nlen]
    if flags & 0x20:                      # KEY_COMP_NAME -> ASCII/latin-1
        return name.decode("latin-1")
    return name.decode("utf-16-le", "replace")


EXT_PATH_FIELDS = {
    "ooxml.external_relationship_targets": ooxml_external_relationship_targets,
    "apk.package_name": apk_package_name,
    "prefetch.executable_name": prefetch_executable_name,
    "pcap.packet_count": pcap_packet_count,
    "evtx.record_count": evtx_record_count,
    "registry.hive_root_name": registry_hive_root_name,
    "email.message_id": email_message_id,
    "media.primary_audio_codec_name": media_primary_audio_codec_name,
    "media.primary_video_dimensions": media_primary_video_dimensions,
    "elf.e_machine_u16_hex": elf_e_machine_u16_hex,
    "macho.cpu_type_set": macho_cpu_type_set,
    "jar.main_class": jar_main_class,
    "sqlite.page_size_bytes": sqlite_page_size_bytes,
    "disk.partition_start_lba_sequence": disk_partition_start_lba_sequence,
    "x509.sha256_fingerprint": x509_sha256_fingerprint,
}
