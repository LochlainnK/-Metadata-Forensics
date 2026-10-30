#!/usr/bin/env python3
"""
solve.py — auto-solver harness for Huntress CTF metadata-forensics challenges.

The full loop, driven by the public questions contract:

    1. start/reconnect the attempt         (gm.sh start)
    2. read questions + artifact list        (gm.sh status)
    3. download every delivery artifact      (gm.sh raw <capability-url>)
    4. unpack nested bundles into a tree
    5. for each question, map (artifact -> member, field) and extract the
       grader-ready value with fmtprobe.py
    6. assemble answers keyed by the exact answer_ids and (optionally) submit
       (gm.sh submit), then report accepted / remaining

Deterministic field/hash/size/zip questions are answered automatically.
Filename-reasoning questions ("first evidence note", "renamed copy") are
resolved from their sibling questions. Unknown fields fall back to an exiftool
tag lookup (flagged for review). Unmappable questions are tagged and skipped.

Speed: extraction runs in parallel, in-process (no per-question subprocess),
downloads run in parallel, and passing several challenge ids solves them
concurrently — each timed attempt on its own clock.

Usage:
    bin/solve.py <challenge-id> [<challenge-id> ...] [--submit] [--timed]
                 [--workdir DIR] [--answers FILE] [--keep]

Network calls go through bin/gm.sh so the bearer token stays in the private
auth config and never touches this process's arguments.
"""
import argparse, json, os, re, subprocess, sys, hashlib, shutil, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
GM = os.path.join(HERE, "gm.sh")

# Import the extractor in-process (sys.path[0] stays this trusted bin/ dir, never
# the untrusted artifact tree) so a 60-question mastery needs zero subprocess
# spawns for parsing — it just calls functions, in parallel.
sys.path.insert(0, HERE)
import fmtprobe  # noqa: E402

MAX_DEPTH = 5
MAX_TOTAL_BYTES = 512 * 1024 * 1024  # zip-bomb guard
MAX_WORKERS = int(os.environ.get("SOLVE_WORKERS", "16"))


def gm(*args, binary=False):
    """Invoke gm.sh; return stdout (text) or raise on failure."""
    r = subprocess.run([GM, *args], capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace"))
        raise SystemExit(f"gm.sh {' '.join(args)} failed ({r.returncode})")
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def gm_json(*args):
    return json.loads(gm(*args))


# --------------------------------------------------------------- unpacking ----
def is_zip(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def extract_tree(artifacts_dir, index, extracted_bytes):
    """Recursively unzip bundles. index maps zip-basename -> contents dir."""
    changed = True
    depth = 0
    while changed and depth < MAX_DEPTH:
        changed = False
        depth += 1
        for root, _dirs, files in os.walk(artifacts_dir):
            for fn in files:
                zpath = os.path.join(root, fn)
                dest = zpath + ".d"
                if os.path.isdir(dest):
                    continue  # already extracted
                # detect zips by magic, not extension: timed modes deliver the
                # bundle via op=artifact with no .zip name.
                if not is_zip(zpath):
                    continue
                os.makedirs(dest, exist_ok=True)
                r = subprocess.run(["unzip", "-o", "-q", zpath, "-d", dest],
                                   capture_output=True)
                if r.returncode not in (0, 1):  # 1 = warnings only
                    sys.stderr.write(
                        f"warn: unzip {fn}: {r.stderr.decode('utf-8', 'replace')}\n")
                index.setdefault(fn, dest)
                for dd, _s, ff in os.walk(dest):
                    for x in ff:
                        try:
                            extracted_bytes[0] += os.path.getsize(os.path.join(dd, x))
                        except OSError:
                            pass
                if extracted_bytes[0] > MAX_TOTAL_BYTES:
                    raise SystemExit("aborting: extracted size exceeds guard limit")
                changed = True


def resolve_member(index, zip_name, member, artifacts_dir, delivery=None):
    """Find the on-disk path for '[delivery N:] <zip_name> -> <member>'.

    When a delivery number is given (multiple deliveries may share a zip name),
    search that delivery's subdir first, then fall back to the whole tree.
    """
    search_roots = []
    if delivery is not None:
        search_roots.append(os.path.join(artifacts_dir, f"delivery-{delivery}"))
    base = index.get(zip_name)
    if base:
        search_roots.append(base)
    search_roots.append(artifacts_dir)  # fallback: anywhere in the tree
    # exact relative path match first
    for rootdir in search_roots:
        if rootdir and os.path.isfile(os.path.join(rootdir, member)):
            return os.path.join(rootdir, member)
    # basename match
    want = os.path.basename(member)
    for rootdir in search_roots:
        if not rootdir or not os.path.isdir(rootdir):
            continue
        for dd, _s, ff in os.walk(rootdir):
            if want in ff:
                return os.path.join(dd, want)
    return None


# --------------------------------------------------------- question parsing ----
GENERIC = [
    (re.compile(r"exact size in bytes", re.I), "size"),
    (re.compile(r"\bMD5\b", re.I), "md5"),
    (re.compile(r"SHA-?1\b", re.I), "sha1"),
    (re.compile(r"SHA-?256\b", re.I), "sha256"),
    (re.compile(r"first sixteen bytes", re.I), "first16"),
]
DETERMINE = re.compile(r"Determine\s+([a-z0-9_.]+)\s+for\s+", re.I)
DIGESTSORT = re.compile(
    r"Compute the full-file\s+(SHA-?256|SHA-?1|MD5)\s+digest.*?"
    r"(ascending|descending)\s+digest order\.\s*Files:\s*(\[.*\])", re.I | re.S)
FILENAME_Q = re.compile(r"exact filename of (?:the )?(.+?)\s*[?.]", re.I)


def parse_field(question):
    # Strip disambiguation tags like "[assigned-artifact-sha256:...]" so their
    # literal "sha256" text can't be mistaken for a digest question.
    q = re.sub(r"\[[^\]]*\]", "", question)
    # structural "Determine <field> for ..." first
    m = DETERMINE.search(q)
    if m:
        return m.group(1), None
    # filename-reasoning questions before the generic hash matchers
    if re.search(r"filename of the first evidence note", q, re.I):
        return None, "first-note"
    if re.search(r"filename of the renamed evidence-note copy", q, re.I):
        return None, "renamed-copy"
    if re.search(r"exact filename", q, re.I):
        return None, "filename-other"
    # generic hash / size / first-bytes
    for rx, name in GENERIC:
        if rx.search(q):
            return name, None
    return None, "unknown"


ART_RX = re.compile(r"^(?:delivery\s+(?P<deliv>\d+):\s*)?(?P<zip>[^->]+?\.zip)\s*(?:->\s*(?P<member>.+))?$", re.I)


def parse_artifact(artifact):
    """'delivery 1: foo.zip -> a/b.txt' -> ('foo.zip', 'a/b.txt', 1)."""
    s = artifact.strip()
    m = ART_RX.match(s)
    if not m:
        if "->" in s:  # no .zip in the ref; maybe a bare file
            z, mem = s.split("->", 1)
            return z.strip(), mem.strip(), None
        return s, None, None
    deliv = int(m.group("deliv")) if m.group("deliv") else None
    return m.group("zip").strip(), (m.group("member") or "").strip() or None, deliv


# ------------------------------------------------- filename-question logic ----
def find_file(artifacts_dir, basename):
    """Locate a file by basename anywhere in the artifact tree."""
    for dd, _s, ff in os.walk(artifacts_dir):
        if basename in ff:
            return os.path.join(dd, basename)
    return None


def zip_members_in_order(zip_path):
    """Direct members (name, bytes) in central-directory order."""
    import zipfile
    out = []
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():          # central-directory order
                if info.is_dir():
                    continue
                out.append((info.filename, zf.read(info)))
    except Exception:
        pass
    return out


_FN_STOP = {"the", "a", "an", "exact", "filename", "file", "of", "named", "its"}

def _tokens(s):
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]

def resolve_filename(keyword, zip_name, sibling_members, artifacts_dir):
    """Resolve 'exact filename of the <keyword>' by matching the keyword's
    content words against candidate member basenames.

    Candidates are the sibling questions' referenced members (they name the
    exact files under test), falling back to the archive's direct members in
    central-directory order. Scoring: most keyword tokens matched, then fewest
    extra tokens; 'first' breaks ties toward central-directory order.
    """
    kw = {t for t in _tokens(keyword) if t not in _FN_STOP}
    want_first = "first" in _tokens(keyword)

    # candidates: sibling-referenced members first, then the zip's own direct
    # members (the target may have no sibling question, e.g. the roster file).
    cands = [os.path.basename(m) for m in sibling_members]
    zpath = find_file(artifacts_dir, os.path.basename(zip_name))
    if zpath:
        cands += [os.path.basename(n) for n, _ in zip_members_in_order(zpath)]
    cands = list(dict.fromkeys(cands))
    scored = []
    for i, c in enumerate(cands):
        ct = set(_tokens(c))
        inter = len(kw & ct)
        if inter:
            scored.append(((inter, -len(ct - kw), -i if want_first else 0), c))
    if scored:
        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[0][0][0]
        tie = [c for s, c in scored if s[0] == top]
        return tie[0], ("" if len(tie) == 1 or want_first else "review(ambiguous)")
    return (cands[0], "review(no-keyword-match)") if cands else (None, "review(empty)")


_HASH = {"sha256": hashlib.sha256, "sha1": hashlib.sha1, "md5": hashlib.md5}

def resolve_digestsort(algo, order, files, index, zip_name, delivery, artifacts_dir):
    """Sort a named file list by their digest and return a compact JSON array
    of the filenames in that order (the 'ascending digest order' questions).

    Each file is resolved WITHIN the question's own set/zip, since a multi-set
    mastery repeats basenames (set1/roster.csv vs set2/roster.csv) with
    different content.
    """
    h = _HASH.get(algo)
    if not h:
        return None, f"digestsort-algo({algo})"
    scored = []
    for fn in files:
        p = resolve_member(index, zip_name, fn, artifacts_dir, delivery)
        if not p:
            return None, f"digestsort-missing({fn})"
        with open(p, "rb") as fh:
            scored.append((h(fh.read()).hexdigest(), fn))
    scored.sort(key=lambda x: x[0], reverse=(order == "descending"))
    return json.dumps([fn for _, fn in scored], separators=(",", ":")), ""


# ---------------------------------------------------------------- solve one ----
def solve_one(challenge, a):
    """Run the full loop for one challenge. Returns a summary dict."""
    pfx = f"[{challenge.split('/')[0].split('-')[-1]}/{challenge.split('/')[-1]}]" \
        if "/" in challenge else f"[{challenge}]"

    workdir = (os.path.join(a.workdir, re.sub(r"[^a-z0-9]+", "-", challenge.lower()))
               if a.workdir else os.path.join(
                   os.environ.get("TMPDIR", "/tmp"),
                   "solve-" + re.sub(r"[^a-z0-9]+", "-", challenge.lower())))
    artifacts_dir = os.path.join(workdir, "artifacts")
    if os.path.isdir(workdir):
        shutil.rmtree(workdir)
    os.makedirs(artifacts_dir, exist_ok=True)

    # 1. start / reconnect  (the countdown begins here for timed modes)
    t_start = time.time()
    start = ["start", challenge] + (["--timed"] if a.timed else [])
    s = gm_json(*start)
    sys.stderr.write(f"{pfx} start: {s.get('result','?')}  {s.get('name','')}\n")

    # 2. status -> questions + artifacts
    st = gm_json("status", challenge)
    questions = st.get("questions") or s.get("questions") or []
    arts = st.get("artifacts") or []
    sys.stderr.write(f"mode={st.get('mode')} deadline={st.get('deadline')} "
                     f"questions={len(questions)} artifacts={len(arts)}\n")

    # 3. download each delivery artifact into its own subdir (delivery-1, ...),
    #    in parallel, so deliveries that share a zip filename don't collide and
    #    multi-delivery fetches overlap.
    def fetch(i_art):
        i, art = i_art
        fn = art.get("filename") or f"artifact-{i+1}.bin"
        ddir = os.path.join(artifacts_dir, f"delivery-{i+1}")
        os.makedirs(ddir, exist_ok=True)
        out = os.path.join(ddir, fn)
        if art.get("download"):
            gm("raw", art["download"], out)
        else:
            gm("artifact", challenge, out)
        want = art.get("sha256")
        if want:
            got = hashlib.sha256(open(out, "rb").read()).hexdigest()
            return f"delivery-{i+1}/{fn} sha256 {'OK' if got == want else 'MISMATCH'}"
        return f"delivery-{i+1}/{fn}"
    if arts:
        with ThreadPoolExecutor(max_workers=min(8, len(arts))) as ex:
            for msg in ex.map(fetch, list(enumerate(arts))):
                sys.stderr.write(f"{pfx}   downloaded {msg}\n")
    else:  # single-artifact fallback
        ddir = os.path.join(artifacts_dir, "delivery-1")
        os.makedirs(ddir, exist_ok=True)
        gm("artifact", challenge, os.path.join(ddir, "artifact.bin"))

    # 4. unpack
    index = {}
    extract_tree(artifacts_dir, index, [0])

    # pre-pass: group member references by set (fallback: by zip) so filename
    # questions can be answered from their sibling questions.
    def group_key(q, zip_name):
        return q.get("set", zip_name)
    group_members = {}
    for q in questions:
        zp, mem, _dl = parse_artifact(q.get("artifact", ""))
        if mem:
            group_members.setdefault(group_key(q, zp), []).append(mem)

    # 5. per-question extraction — resolve jobs, then run them in parallel.
    t_resolve = time.time()
    jobs = []   # (idx, qid, label, tgt, kind, payload)
    for idx, q in enumerate(questions):
        qid = q.get("id")
        field, special = parse_field(q.get("question", ""))
        qtext = q.get("question", "")
        zip_name, member, delivery = parse_artifact(q.get("artifact", ""))

        # compound: sort a named file list by digest (capstone question)
        dm = DIGESTSORT.search(qtext)
        if dm:
            algo = dm.group(1).lower().replace("-", "")
            order = dm.group(2).lower()
            try:
                files = json.loads(dm.group(3))
            except Exception:
                files = []
            jobs.append((idx, qid, f"digest-sort[{algo}]", f"{len(files)} files",
                         "digestsort", (algo, order, files, zip_name, delivery)))
            continue
        # any "exact filename of the <keyword>" question
        fm = FILENAME_Q.search(qtext)
        if fm:
            sibs = group_members.get(group_key(q, zip_name), [])
            jobs.append((idx, qid, f"filename:{fm.group(1).strip()[:18]}", zip_name,
                         "filename", (fm.group(1).strip(), zip_name, sibs)))
            continue

        field, special = parse_field(qtext)
        label = field or special or "?"
        tgt = member or zip_name
        if field is None:
            jobs.append((idx, qid, label, tgt, "unmapped", None))
        else:
            path = resolve_member(index, zip_name, member, artifacts_dir, delivery) if member \
                else resolve_member(index, zip_name, zip_name, artifacts_dir, delivery)
            if not path:
                jobs.append((idx, qid, label, tgt, "notfound",
                             f"{zip_name} -> {member}"))
            else:
                jobs.append((idx, qid, label, tgt, "field", (field, path)))

    # read each unique byte-field target once (threads only read the cache)
    byte_cache = {}
    for _i, _q, _l, _t, kind, payload in jobs:
        if kind == "field":
            field, path = payload
            if field in fmtprobe.BYTE_FIELDS and path not in byte_cache:
                with open(path, "rb") as fh:
                    byte_cache[path] = fh.read()

    def run_job(job):
        idx, qid, label, tgt, kind, payload = job
        val, note = None, ""
        try:
            if kind == "filename":
                keyword, zip_name, sibs = payload
                val, note = resolve_filename(keyword, zip_name, sibs, artifacts_dir)
            elif kind == "digestsort":
                algo, order, files, zip_name, delivery = payload
                val, note = resolve_digestsort(algo, order, files, index,
                                               zip_name, delivery, artifacts_dir)
            elif kind == "unmapped":
                note = "UNMAPPED-QUESTION"
            elif kind == "notfound":
                note = f"FILE-NOT-FOUND({payload})"
            elif kind == "field":
                field, path = payload
                if field in fmtprobe.BYTE_FIELDS:
                    val = fmtprobe.BYTE_FIELDS[field](byte_cache[path])
                elif field in fmtprobe.PATH_FIELDS:
                    val = fmtprobe.PATH_FIELDS[field](path)
                    if val is None:
                        note = f"PROBE-NULL({field})"
                else:   # unknown field -> exiftool fallback (generalization)
                    val = fmtprobe.compute(path, field)
                    note = "exiftool-guess" if val is not None else f"UNMAPPED-FIELD({field})"
        except Exception as e:  # never let one question sink the batch
            note = f"PROBE-ERR:{str(e)[:50]}"
        return (idx, qid, label, tgt, val, note)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(run_job, jobs))
    results.sort(key=lambda r: r[0])

    answers, report = {}, []
    for _idx, qid, label, tgt, val, note in results:
        if val is not None and not note.startswith(("FILE", "PROBE", "UNMAPPED")):
            answers[qid] = val
        report.append((qid, label, tgt, val, note))
    sys.stderr.write(f"extracted {len(answers)}/{len(questions)} in "
                     f"{time.time()-t_resolve:.2f}s "
                     f"({MAX_WORKERS} workers)\n")

    # report
    lines = [f"\n=== {challenge} : {len(answers)}/{len(questions)} auto-answered ==="]
    review = [r for r in report if r[4]]
    for qid, field, tgt, val, note in report:
        tag = f"  [{note}]" if note else ""
        shown = "" if val is None else (val if len(val) <= 60 else val[:57] + "...")
        lines.append(f"  {field:34s} {str(tgt)[:30]:30s} = {shown}{tag}")
    if review:
        lines.append(f"\n  {len(review)} question(s) need review "
                     f"(see [review]/[...] tags above)")
    print("\n".join(lines))

    if a.answers and len(questions) and not os.path.isdir(a.answers):
        # single-challenge convenience; for many challenges pass a dir
        with open(a.answers, "w") as fh:
            json.dump(answers, fh, ensure_ascii=False)
        print(f"\nwrote answers -> {a.answers}")

    # 6. submit  (batched: one submission for the whole mastery)
    result = None
    if a.submit and answers:
        af = os.path.join(workdir, "answers.json")
        with open(af, "w") as fh:
            json.dump(answers, fh, ensure_ascii=False)
        res = gm_json("submit", challenge, "--json", af)
        # If a timed attempt lapsed (we were too slow, or no variants remain),
        # the server replies "expired". Fall back to untimed practice — which
        # continues on the same artifact — and resubmit so the mode still
        # completes autonomously.
        if res.get("result") == "expired":
            sys.stderr.write(f"{pfx} attempt expired; continuing in practice\n")
            gm("practice", challenge)
            res = gm_json("submit", challenge, "--json", af)
        result = res.get("result")
        print(f"\n=== {challenge} submit ===")
        print(json.dumps({k: res.get(k) for k in
              ("result", "message", "accepted_ids", "remaining", "incorrect_ids")
              if k in res}, indent=2))
    elif a.submit:
        print(f"\n{pfx} nothing to submit (no answers computed)")

    elapsed = time.time() - t_start
    print(f"{pfx} start -> {'submit' if a.submit else 'answers ready'}: {elapsed:.2f}s")
    return {"challenge": challenge, "answered": len(answers),
            "total": len(questions), "review": len(review),
            "result": result, "elapsed": elapsed}


# --------------------------------------------------------------------- main ----
def main():
    ap = argparse.ArgumentParser(
        description="Auto-solve one or more Huntress metadata-forensics challenges.")
    ap.add_argument("challenge", nargs="+",
                    help="challenge id(s); several are solved concurrently")
    ap.add_argument("--submit", action="store_true", help="submit computed answers")
    ap.add_argument("--timed", action="store_true", help="opt into a timed attempt")
    ap.add_argument("--workdir", default=None, help="base work dir (a subdir per challenge)")
    ap.add_argument("--answers", default=None, help="write answers JSON here (single challenge)")
    ap.add_argument("--keep", action="store_true", help="keep work dirs")
    ap.add_argument("--require-complete", action="store_true",
                    help="exit non-zero (3) unless every question was answered; "
                         "used to gate timed modes behind a clean single_solve")
    a = ap.parse_args()

    chs = a.challenge
    if len(chs) == 1:
        summaries = [solve_one(chs[0], a)]
    else:
        # Solve multiple challenges in parallel so each timed attempt runs on
        # its own clock and the whole set finishes in about the slowest's time.
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=min(len(chs), 8)) as ex:
            summaries = list(ex.map(lambda c: solve_one(c, a), chs))
        print("\n================= summary =================")
        for s in sorted(summaries, key=lambda x: x["challenge"]):
            rslt = f" result={s['result']}" if s["result"] else ""
            rev = f" review={s['review']}" if s["review"] else ""
            print(f"  {s['challenge']:52s} {s['answered']}/{s['total']}"
                  f" {s['elapsed']:.1f}s{rslt}{rev}")
        print(f"  wall time for {len(chs)} challenges: {time.time()-t0:.1f}s")

    # exit-code contract: 3 means at least one challenge was not fully answered
    incomplete = [s for s in summaries if s["answered"] < s["total"]]
    if a.require_complete and incomplete:
        sys.stderr.write(f"require-complete: {len(incomplete)} challenge(s) "
                         f"not fully answered\n")
        sys.exit(3)


if __name__ == "__main__":
    main()
