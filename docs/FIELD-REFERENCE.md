# Field reference — how each value is derived

`fmtprobe.py` reads the real bytes and returns each value already formatted to
the grader's `answer_format.syntax`. This is the authoritative list of what it
knows, where the value comes from, and the exact output shape.

> When the requested field is genuinely absent, the grader wants the literal
> `none`. `fmtprobe` returns `none` for that case.

## Generic (any file)

| Field | Output | Source |
|-------|--------|--------|
| `size`     | base-10 integer | byte length |
| `md5`      | 32 hex (lower) | `hashlib.md5` |
| `sha1`     | 40 hex (lower) | `hashlib.sha1` |
| `sha256`   | 64 hex (lower) | `hashlib.sha256` |
| `first16`  | 32 hex (lower), no `0x`/spaces | first 16 bytes |

These answer the "What is its … digest / size / first sixteen bytes" questions.
Digests are graded case-insensitively; everything else is `trim`.

## Structural (byte-parsed, no external tool)

| Field | Output | How it's read |
|-------|--------|---------------|
| `jpeg.sof_dimensions_pixels` | `WxH` | scan markers to the SOF (`FFC0`-`FFCF`, skipping `FFC4/C8/CC`); height@+5, width@+7 (big-endian) |
| `png.ihdr_dimensions_pixels` | `WxH` | first chunk after the 8-byte signature is `IHDR`; width@+16, height@+20 (big-endian u32) |
| `pdf.header_version` | `X.Y` | the literal `%PDF-X.Y` header (searched in the first 1 KiB; the version string only, not the catalog `/Version`) |
| `text.utf8_bom_present` | `true`/`false` | leading bytes equal `EF BB BF` |
| `zip.eocd_total_entries` | integer | "total central-directory records" u16 @ EOCD+10 (ZIP64 EOCD fallback when saturated) |
| `zip.central_directory_member_names` | compact JSON array | walk the central-directory headers (`PK\x01\x02`) in order; names only |
| `pe.coff_machine_u16_hex` | `0xNNNN` (u16, 4 digits) | COFF `Machine` u16 @ `e_lfanew`+4 |
| `pe.address_of_entry_point_rva_hex` | `0x…` (minimal) | Optional-header `AddressOfEntryPoint` u32 @ `e_lfanew`+24+16 |

Why parse bytes instead of trusting a tool? The whole lane is about
*structure vs. presentation* — a renamed `.png` that is really a JPEG, a "clean"
file with a hidden BOM, a resized image whose SOF still holds the true size.
Reading the structure is the point.

## Needs an external parser

| Field | Output | Tool |
|-------|--------|------|
| `pe.version_original_filename` | the `OriginalFilename` string | `exiftool -OriginalFileName` (reads `VS_VERSION_INFO`) |
| `dotnet.mvid_guid` | canonical `8-4-4-4-12` lowercase | `dnfile` → Module table `Mvid` → `uuid.UUID(bytes_le=…)` |
| `msi.product_code_guid` | `{8-4-4-4-12}` (as stored) | `msiinfo export <f> Property` → `ProductCode` row |

### GUID format notes

- **MVID** (`.NET`): `dnfile` gives 16 raw bytes; a System.Guid serializes its
  first three fields little-endian, so `uuid.UUID(bytes_le=…)` yields the
  canonical lowercase hyphenated form the grader's `pattern` expects.
- **MSI ProductCode**: `msiinfo` returns it wrapped in braces and uppercased
  (`{DD1A80D5-…}`). The `pattern` grader keys on the `8-4-4-4-12` hex with
  hyphens; braces/case are the one thing to re-check on a live, unsolved
  challenge — submit, and if it bounces, try the braceless lowercase form.

## Unknown fields — the exiftool fallback (generalization)

For a `Determine <prefix>.<field>` question with no dedicated parser,
`fmtprobe.compute()` maps the field's last component to an exiftool tag
(dropping `_u16/_hex/_pixels/_bytes/_guid/_rva/_string/_text` hints) and returns
that tag's value, printing `… via exiftool tag X (verify format)`. `solve.py`
submits it but flags it `[exiftool-guess]` so you can eyeball the format. This
is what lets the toolkit take a swing at day-14+ fields it has never seen.

## Adding a dedicated field in ~5 minutes

1. `bin/dig.sh <artifact>` — see the bytes, exiftool tags, and layout.
2. Read the question's `answer_format.syntax` — it states the exact shape.
3. In `bin/fmtprobe.py` write `def mytype_myfield(b): ...` (bytes in, string
   out) and register it in `BYTE_FIELDS` (or `PATH_FIELDS` if it shells out to a
   tool). Add a magic test to `MAGIC_FIELDS` so `auto` mode surfaces it.
4. `bin/fmtprobe.py <file> --field mytype.myfield` to check it.

`solve.py` needs no change — it keys off the question text and will route the
new field to your function automatically.
