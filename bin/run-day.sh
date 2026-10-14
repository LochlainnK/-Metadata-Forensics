#!/usr/bin/env bash
#
# run-day.sh — solve a metadata-forensics day in the right order:
#
#     1. single_solve   (untimed) — learn/validate the approach on the free
#                        static artifact. This is the GATE: if the solver can't
#                        fully answer the single_solve, we stop here rather than
#                        burn a timed attempt on a field we don't yet handle.
#     2. time_trial      — the same knowledge against the countdown.
#     3. mastery         — the bundle; its many files are extracted in parallel
#                          by solve.py (one batched submission).
#
# Usage:
#     run-day.sh <day-number>            e.g. run-day.sh 4
#     run-day.sh <base-challenge-id>     e.g. run-day.sh metadata-forensics-day-04-picture-this
#
# Options (passed through to solve.py for the timed modes):
#     --timed        opt into timed Hall-of-Fame attempts for time_trial/mastery
#     --dry          compute only; do not submit anything
#     --force        run time_trial/mastery even if the single_solve gate fails
#
# The single_solve step always submits (it is untimed and safe); use --dry to
# make the whole run compute-only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GM="$HERE/gm.sh"
SOLVE="$HERE/solve.py"
LANE="metadata-forensics"

TIMED=""; DRY=""; FORCE=""
ARGS=()
for a in "$@"; do
  case "$a" in
    --timed) TIMED="--timed" ;;
    --dry)   DRY="1" ;;
    --force) FORCE="1" ;;
    *)       ARGS+=("$a") ;;
  esac
done
target="${ARGS[0]:?usage: run-day.sh <day-number|base-challenge-id> [--timed] [--dry] [--force]}"

# Resolve the base (single_solve) challenge id.
if [[ "$target" == *metadata-forensics-day-* ]]; then
  base="${target%%/*}"                       # strip any /time_trial|/mastery
else
  # treat as a day number: look it up in the live listing (future-proof)
  base="$("$GM" list "day=$target" 2>/dev/null | jq -r \
    --arg lane "$LANE" \
    '.challenges[] | select(.lane==$lane and .mode=="single_solve") | .id' | head -1)"
  [[ -n "$base" ]] || { echo "run-day: no $LANE single_solve found for day $target" >&2; exit 1; }
fi

submit="--submit"; [[ -n "$DRY" ]] && submit=""
echo "═══ day flow for: $base ═══"

# 1. single_solve — the gate (untimed, always safe to submit)
echo; echo "── [1/3] single_solve (gate) ──"
gate_ok=1
if python3 -I "$SOLVE" "$base" $submit --require-complete; then
  echo "gate: single_solve fully solved ✓"
else
  gate_ok=0
  echo "gate: single_solve NOT fully solved ✗" >&2
fi

if [[ "$gate_ok" -eq 0 && -z "$FORCE" ]]; then
  cat >&2 <<EOF

Stopping before timed modes: the single_solve left questions unanswered
(look for [UNMAPPED]/[FILE-NOT-FOUND]/[review] above). Teach fmtprobe.py the
new field (see docs/FIELD-REFERENCE.md), then re-run. Use --force to proceed
anyway.
EOF
  exit 3
fi

# 2. time_trial — same knowledge, now against the clock.
echo; echo "── [2/3] time_trial ──"
python3 -I "$SOLVE" "$base/time_trial" $submit $TIMED || true

# 3. mastery — the bundle; its multiple files are extracted in parallel inside
#    solve.py (in-process thread pool), then submitted in one batch.
echo; echo "── [3/3] mastery (files extracted in parallel) ──"
python3 -I "$SOLVE" "$base/mastery" $submit $TIMED || true

echo; echo "═══ flags earned ═══"
for m in "" "/time_trial" "/mastery"; do
  printf '  %-12s %s\n' "single_solve${m:+ }${m#/}" "$("$GM" flag "$base$m" 2>/dev/null)"
done
