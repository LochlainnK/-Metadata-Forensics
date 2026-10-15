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
| 15 | A Word to the Wise | OOXML (`.docx`) relationships: external vs internal | `ooxml.external_relationship_targets` (+ cumulative review of all prior fields, a per-set SHA-256 **synthesis** ordering, and `roster.csv` / note-vs-copy filename questions) | 100 |

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

## Timed vs. regular, and partial scoring (learned live on day 15)

The API evolved since day 14 — current behaviour:

- **`time_trial`/`mastery` are untimed "regular" scored challenges by default**
  (`deadline: null`). Only `run_for_time:true` (solve.py's `--timed`) requests
  a timed Hall-of-Fame attempt with a countdown. Solve them untimed unless you
  specifically want a ranked time — there is no clock to race.
- **Untimed submits give partial, cumulative feedback**: a submission whose
  answers are all correct returns `result:"accepted"` with `accepted_ids` and a
  decreasing `remaining`; a submission containing any wrong/missing answer
  returns `result:"incorrect"` and records nothing from that batch. So to
  isolate a wrong field, submit answers **one at a time** — the ids that come
  back `incorrect` are the culprits. (Timed attempts grade all-or-nothing.)
- **`start` always reconnects** to the current attempt; **`retry`** advances to
  a *distinct* variant (regular or timed per `run_for_time`). `solve.py --retry`
  does this in-process. Each `retry` is a fresh variant whose files — and whose
  exact question mix — differ, so nail output formats rather than iterating.
- **`mastery` is prerequisite-gated**: it returns `error:"prerequisite_required"`
  until that day's `single_solve`/`time_trial` are solved. Run the modes in
  order (`run-day.sh` already does).
- The mastery bundle holds `evidence-01.zip` … `-05.zip` (one *set* each, 20 Qs).
  Set-scoped questions (the SHA-256 synthesis ordering, note-vs-copy filenames)
  must be resolved **within their own set's zip**, or every set inherits set-1's
  answer.

## Theme notes (what the "trick" actually is)

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
- **Day 15 "A Word to the Wise"** — a `.docx` is a zip of OOXML parts; its
  `*.rels` relationships split into internal (relative, package-local) and
  external (`TargetMode="External"`). The answer is the sorted list of external
  `Target`s — the document "reaching somewhere it should not". The mastery
  bundle layers a cumulative review of every prior field across five sets, a
  per-set SHA-256 synthesis (filenames ordered by ascending digest), and
  note-vs-copy filename questions (`evidence-note.txt` is the original "first
  note"; `evidence-note-copy.txt` is the renamed copy with identical bytes).
