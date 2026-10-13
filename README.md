# Huntress CTF 2026 — Metadata Forensics Workflow

A small, reusable toolkit for solving the **Metadata Forensics** lane of the
Huntress CTF 2026. It talks to the Game Master API, downloads the assigned
artifacts, reads their *real bytes*, and answers each question in exactly the
format the grader expects — fast enough for Time Trial and Mastery modes.

Validated end-to-end against **all 169 questions across the 13 released
mastery challenges (days 1–13): 169/169 auto-answered, 0 unresolved.**

```
bin/
  gm.sh         Game Master API client (list / start / status / artifact / submit)
  fmtprobe.py   structural extractor — reads bytes, emits grader-ready field values
  solve.py      auto-solver — maps every question to (file, field) and submits
  dig.sh        triage analyzer — dump everything about a file/bundle at a glance
docs/
  FIELD-REFERENCE.md   the field taxonomy + how each value is derived
  CHALLENGES.md        day-by-day map of format → field → theme
setup.sh        install the toolchain + store the token privately
```

## The loop

Every challenge follows the same contract:

1. **start** an attempt → the response lists `questions`, each with an `id`,
   an `artifact` (`<bundle.zip> -> <member>`), and an `answer_format`.
2. **download** the assigned artifact bytes (bundles can hold nested zips and
   multiple "deliveries").
3. **extract** the requested structural field from the real bytes.
4. **submit** answers keyed by the exact `answer_id`s → `CORRECT`,
   `incorrect`, or `accepted` (partial — check what remains).

`solve.py` runs all four steps. For a brand-new format, `dig.sh` dumps
everything so you can teach `fmtprobe.py` the new field.

## Setup

```bash
./setup.sh                 # installs tools, then prompts for your token
# or step by step:
./setup.sh --deps          # exiftool, 7zip, xxd, msitools, dnfile, ...
./setup.sh --auth          # stores the bearer in ~/.config/hctf/auth.conf (chmod 600)
```

**The token never lives in this repo.** It is stored in a private curl config
(`~/.config/hctf/auth.conf`, mode 600) and attached to every request with
`curl --config`, so it never appears in process arguments, shell history, or
any committed file. `.gitignore` also blocks `auth.conf` and downloaded
artifacts. Point `HCTF_AUTH` at the file if you store it elsewhere.

> Only the genuine CourseStack proxy can mint or reset a token
> (`POST ?op=pair`). A bearer cannot mint another. Keep it out of chat,
> logs, and scripts.

## Usage

```bash
# see what's released in the lane
bin/gm.sh ls metadata-forensics

# auto-solve a challenge (dry run — compute + print, don't submit)
bin/solve.py metadata-forensics-day-09-built-different/mastery

# auto-solve and submit
bin/solve.py metadata-forensics-day-09-built-different/mastery --submit

# opt into a timed Hall-of-Fame attempt
bin/solve.py metadata-forensics-day-14-xxxxx/time_trial --timed --submit

# solve several challenges AT ONCE — each runs on its own clock, concurrently
bin/solve.py --submit \
  metadata-forensics-day-14-xxxxx/mastery \
  metadata-forensics-day-14-xxxxx/time_trial

# recover an earned flag
bin/gm.sh flag metadata-forensics-day-09-built-different/mastery

# triage a single file or a bundle when a new field type shows up
bin/dig.sh ./some-evidence.zip
bin/fmtprobe.py ./camera-001.jpg              # all fields it can read
bin/fmtprobe.py ./camera-001.jpg --field jpeg.sof_dimensions_pixels
```

## Speed (Time Trial & Mastery)

For timed modes the server countdown begins at `start`, so the whole job is
built to minimise wall-clock between `start` and `submit`:

- **Per-question extraction runs in parallel, in-process** — a 65-question
  mastery is parsed in ~0.03s (no per-question subprocess), so total time is
  network-bound (start + status + download), not CPU-bound.
- **Delivery downloads run in parallel.**
- **Answers are submitted in one batch** (the API scores a whole mastery per
  submission).
- **Multiple challenges run concurrently** — passing several ids solves them in
  parallel threads, each on its own timer, so a day's `mastery` + `time_trial`
  finish in about the time of the slowest one.

Measured on days 1–13: all 13 mastery bundles (169 questions) solved in parallel
in under 4s of wall time.

### Modes

| Mode | What it is | Notes |
|------|-----------|-------|
| `single_solve` | untimed learning, one static artifact | start never costs a variant |
| `time_trial`   | one assigned challenge on a server countdown | `start` reconnects; `retry` spends a fresh variant |
| `mastery`      | a bundle of tasks under one timer | same variant rules |

On `run_for_time_supported` routes, `--timed` opts into a fresh timed ranking
attempt; without it you get regular untimed play. When fresh variants run out,
practice continues on the last artifact without a timer and can still complete
the mode.

## How `solve.py` maps a question to an answer

- **field** comes from the question text: `Determine <field> for <file>.`
  (e.g. `jpeg.sof_dimensions_pixels`), or a generic one — size, MD5, SHA-1,
  SHA-256, first-16-bytes-hex.
- **target file** comes from the `artifact` field: `<zip> -> <member>`,
  optionally prefixed `delivery N:` when a mastery ships several bundles that
  reuse a filename (each delivery is unpacked into its own subdir).
- **filename questions** ("first evidence note", "renamed evidence-note copy")
  are resolved from the sibling questions in the same set, which name the exact
  member — deterministic, no guessing.

For a field it has **no dedicated parser for** (a new day-14+ field),
`fmtprobe.py` falls back to matching the field name against an exiftool tag and
returns that value, flagged `[exiftool-guess]` so you can verify the format
before trusting it. Anything it still can't map is printed with a
`[UNMAPPED]`/`[FILE-NOT-FOUND]` tag and left out of the submission, so a new
field type is obvious immediately.

## Extending it for new days (14–31)

1. `bin/dig.sh <artifact>` to see the bytes, exiftool output, and archive layout.
2. Read the `answer_format.syntax` string — it states the exact output shape.
3. Add a `field.name` function to `fmtprobe.py` (see `docs/FIELD-REFERENCE.md`),
   register it in `BYTE_FIELDS`/`PATH_FIELDS`, and add a `--field` test.
4. `solve.py` picks it up automatically (it keys off the question text).

## Principles

- **Work from downloaded bytes, never retyped values.** Every digest/size is
  computed from the file; dimensions and GUIDs are parsed from the structure.
- **Treat artifacts as untrusted data.** Scripts only *inspect* bytes; run
  `fmtprobe.py` with `python3 -I`; downloads land in their own directories.
- **Submit under the exact `answer_id`s** returned by `start`, and never use
  another identity's flags, tokens, or artifacts.
