# Metadata Forensics — day-by-day map (days 1–13)

> These 13 days are **examples**, not the whole lane. More days (14–31) will be
> released and may introduce new formats and fields. The workflow is built to
> generalize: `solve.py` keys off the question contract, and `fmtprobe.py` falls
> back to an exiftool tag lookup for fields it hasn't been taught yet. Use this
> table as a pattern library for the *kinds* of tricks to expect, and
> `docs/FIELD-REFERENCE.md` for how to add a new field in minutes.

Each day teaches one structural field (or a theme) in `single_solve`, then
tests it across more files in `time_trial` and `mastery`. The **Mastery Q**
column is the number of questions in the mastery bundle. Every one of these
169 questions is auto-answered by `bin/solve.py`.

| Day | Name | Theme / trick | Primary field(s) | Mastery Q |
|----:|------|---------------|------------------|----------:|
| 1 | You Must Be This Hash to Ride | hash & size integrity; spot the renamed copy | `md5` `sha1` `sha256` `size` + filename | 10 |
| 2 | Looks Can Be Deceiving | the extension lies — read the magic bytes | `first16` | 2 |
| 3 | BOM Voyage | a UTF-8 BOM hides at the front of a "clean" file | `text.utf8_bom_present` | 2 |
| 4 | Picture This | JPEG resized/renamed; true size is in the SOF | `jpeg.sof_dimensions_pixels` | 16 |
| 5 | Chunk Norris | PNG dimensions live in the IHDR chunk | `png.ihdr_dimensions_pixels` | 2 |
| 6 | Portable Deception | the PDF header version vs. what it claims | `pdf.header_version` | 2 |
| 7 | Seven-Zip, No Relation | ZIP central directory vs. what you see | `zip.eocd_total_entries` `zip.central_directory_member_names` | 2 |
| 8 | What's in the Box? | everything at once, nested bundles | all of the above | 60 |
| 9 | Built Different | identical-looking files, different builds | all of the above + `pe.coff_machine_u16_hex` | 65 |
| 10 | Where Do We Begin? | PE execution entry point | `pe.address_of_entry_point_rva_hex` | 2 |
| 11 | What's My Name Again? | filenames randomized; PE version resource remembers | `pe.version_original_filename` | 2 |
| 12 | Managed Expectations | .NET assemblies: rebuilds vs. renames | `dotnet.mvid_guid` | 2 |
| 13 | Product Placement | MSI installers: revisions vs. collisions | `msi.product_code_guid` | 2 |
| 14 | The Shortcut Home | Windows `.lnk` shortcuts: read where each points | `lnk.target_path_windows` | 2 |
| 15 | Word to the Wise | OOXML external relationships (docx) | `ooxml.external_relationship_targets` | — |
| 16 | Return to Sender | email headers + **capstone** (all prior fields) | `email.message_id` + synthesis | 105 |
| 17 | Hear Me Out | audio codec (ffprobe) | `media.primary_audio_codec_name` | 110 |
| 18 | Frame of Reference | video dimensions (ffprobe) | `media.primary_video_dimensions` | 115 |
| 19 | Little Endian on the Prairie | ELF machine type | `elf.e_machine_u16_hex` | 120 |
| 20 | Universal Appeal | Mach-O universal binary CPU types | `macho.cpu_type_set` | 125 |
| 21 | Package Deal | APK package name (binary AXML) | `apk.package_name` | 130 |
| 22 | Main Character Energy | JAR Main-Class | `jar.main_class` | 162 |
| 23 | Page Me Maybe | SQLite page size | `sqlite.page_size_bytes` | 196 |
| 24 | Event Horizon | EVTX record count | `evtx.record_count` | 232 |
| 25 | Hive Mind | registry hive root key | `registry.hive_root_name` | 270 |
| 26 | Before You Go | Windows Prefetch exe name (LZXPRESS) | `prefetch.executable_name` | 310 |
| 27 | Packet Loss Prevention | pcap/pcapng packet count | `pcap.packet_count` | 352 |
| 28 | Where It All Began | disk image GPT/MBR partition LBAs | `disk.partition_start_lba_sequence` | 396 |
| 29 | Trust Issues | X.509 certificate SHA-256 fingerprint | `x509.sha256_fingerprint` | 442 |
| 30 | Seeing Double | cluster of files: group identical content by SHA-256 | `relation.identical_sha256_groups` | 490 |
| 31 | No Artifact Left Behind | reconstruct the execution/delivery chain from cross-artifact metadata; reject the decoy cycle | `graph.execution_chain_artifact_ids` | 540 |

From day 16 the `time_trial`/`mastery` modes are **cumulative capstones**: one
`evidence.zip` (mastery: 5 sets) carrying every field type seen so far, plus a
"filename of the \<thing\>" and a "sort files by digest" synthesis question. They
grade all-or-nothing. All 45 modes of days 15–29 are solved by this workflow.

## Recurring artifact shape

- A challenge ships one or more **delivery** bundles (`metadata-day-NN-evidence*.zip`).
- A mastery bundle (`...-mastery.zip`) usually contains several inner evidence
  zips (`metadata-day-NN-evidence-01.zip` … `-05.zip`), one per *set*.
- Each evidence zip holds the files under test, e.g. `camera-001.jpg`,
  `panel-001.png`, `document-001.pdf`, `evidence-drop-001.zip`,
  `telemetry-agent-001.exe`, `evidence-note.txt`.
- The `evidence-note.txt` is the target of the hash/size/first16/BOM and
  filename questions; `evidence-drop-*.zip` is the target of the `zip.*`
  questions.

## Timed-mode mechanics (learned live on day 14)

- `time_trial`/`mastery` on legacy routes (`run_for_time_supported=false`) start
  the countdown on the first `start` — a tight window (~30s on day 14). The
  parallel solver does start→download→extract→submit in ~2–3s, well inside it.
- For timed modes, `status` lists **no** artifacts; the bundle comes from
  `op=artifact` (solve.py's fallback), and it may be a zip with **no `.zip`
  name** — extraction keys off the `PK\x03\x04` magic, not the extension.
- When a timed attempt lapses or variants are exhausted, the server replies
  `expired`. `solve.py` then issues `op=practice` (untimed continuation on the
  same artifact) and resubmits automatically, so the mode still completes.

## Theme notes (what the "trick" actually is)

- **Day 2 / Day 4 / Day 5 / Day 6** — the *presentation* (filename, extension,
  on-screen size) is made to disagree with the *structure* (magic bytes, SOF,
  IHDR, `%PDF-` header). Always read the structure.
- **Day 9 "Built Different"** — the five evidence sets look pixel-identical but
  differ in a build-level field (e.g. the PE `coff_machine` or a hash). The
  tool extracts the differing field for each so the odd one out is obvious.
- **Day 11 impersonator** — renamed PE binaries still carry their original
  `OriginalFilename` in the version resource; one of them is lying.
- **Day 12 rebuild vs rename** — same assembly name/version, but the module
  `Mvid` GUID is unique per build; a rename keeps the Mvid, a rebuild changes it.
- **Day 13 collision** — two installers copied/repackaged share the same
  `ProductCode` GUID — that shared code is the collision.
