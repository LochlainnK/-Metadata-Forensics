#!/usr/bin/env bash
#
# gm.sh — Huntress CTF 2026 "Game Master" API client for metadata-forensics work.
#
# The bearer token is NEVER stored in this repo. It lives in a private curl
# config file (mode 0600) referenced by $HCTF_AUTH, and is attached to every
# request with `curl --config` so it never appears in process arguments.
#
# One-time setup (outside the repo):
#     mkdir -p ~/.config/hctf && umask 077
#     printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > ~/.config/hctf/auth.conf
#     unset TOKEN
#
# Environment:
#     HCTF_AUTH   path to the curl config holding the Authorization header
#                 (default: ~/.config/hctf/auth.conf)
#     HCTF_BASE   API base URL (default: https://2026.huntress.ctf.games)
#
# Usage:
#     gm.sh list [day=N] [lane=X] [all] [search=TEXT]   list challenges (raw JSON)
#     gm.sh ls                                          compact table of all challenges
#     gm.sh start  <challenge> [--timed]                start/reconnect an attempt
#     gm.sh retry  <challenge> [--timed]                spend a fresh variant (timed modes)
#     gm.sh status <challenge>                          attempt status (+ flag once solved)
#     gm.sh flag   <challenge>                          just the earned flag
#     gm.sh artifact <challenge> <outfile>              download assigned artifact bytes
#     gm.sh submit <challenge> id1=ans1 [id2=ans2 ...]  submit one or more answers
#     gm.sh submit <challenge> --json <file.json>       submit a prebuilt answers object
#     gm.sh openapi                                     print the live API spec
#
# All gameplay POSTs send Content-Type: application/json. Submit builds its JSON
# with jq so answer values are escaped correctly.
set -euo pipefail

HCTF_BASE="${HCTF_BASE:-https://2026.huntress.ctf.games}"
HCTF_AUTH="${HCTF_AUTH:-$HOME/.config/hctf/auth.conf}"

die() { printf 'gm.sh: %s\n' "$*" >&2; exit 1; }

[[ -f "$HCTF_AUTH" ]] || die "auth config not found at '$HCTF_AUTH'. Set HCTF_AUTH or create it (see header of this script)."
command -v curl >/dev/null || die "curl is required"
command -v jq   >/dev/null || die "jq is required"

# curl with the private auth header + sane transfer/retry behaviour.
_curl() { curl -sS --config "$HCTF_AUTH" --retry 4 --retry-delay 2 --retry-connrefused "$@"; }

_get()  { _curl "$HCTF_BASE/$1"; }
_post() { _curl -H 'Content-Type: application/json' -d "$2" "$HCTF_BASE/$1"; }

cmd="${1:-}"; shift || true

case "$cmd" in
  list)
    q="?op=list"
    for a in "$@"; do q="$q&$a"; done
    _get "$q"
    ;;

  ls)
    # Compact, sortable table of every released challenge. Optional substring
    # filter: `gm.sh ls metadata` keeps rows whose id/name/lane match.
    filter="${1:-}"
    _get "?op=list&all=true" | jq -r '
      .challenges
      | sort_by(.day, .lane, .mode)
      | ["DAY","MODE","LANE","ID","NAME"],
        (.[] | [(.day|tostring), .mode, .lane, .id, .name])
      | @tsv' \
    | awk -F'\t' -v f="$filter" '
        f=="" || tolower($0) ~ tolower(f) || NR==1 {
          printf "%-4s %-13s %-28s %-52s %s\n",$1,$2,$3,$4,$5
        }'
    ;;

  start|retry|practice)
    # start   -> {challenge}                 (begin/reconnect)
    # retry   -> {op:retry,challenge}         (spend a fresh variant)
    # practice-> {op:practice,challenge}      (untimed continuation once variants
    #                                          are exhausted; completes the mode)
    ch="${1:?challenge id required}"; shift || true
    timed=false
    for a in "$@"; do [[ "$a" == "--timed" ]] && timed=true; done
    body=$(jq -nc --arg ch "$ch" --argjson t "$timed" --arg op "$cmd" \
      'if $op=="start" then {challenge:$ch} else {op:$op,challenge:$ch} end
       | if $t then . + {run_for_time:true} else . end')
    _post "" "$body"
    ;;

  status)
    ch="${1:?challenge id required}"
    _get "?op=status&challenge=$ch"
    ;;

  flag)
    ch="${1:?challenge id required}"
    _get "?op=status&challenge=$ch" | jq -r '.flag // "«no flag yet»"'
    ;;

  artifact)
    ch="${1:?challenge id required}"
    out="${2:?output file required}"
    mkdir -p "$(dirname "$out")"
    _curl "$HCTF_BASE/?op=artifact&challenge=$ch" -o "$out"
    printf 'saved %s\n' "$out" >&2
    file "$out" >&2 || true
    ;;

  raw)
    # Fetch an arbitrary API path (e.g. a status .artifacts[].download capability
    # URL) with the private auth header. Usage: gm.sh raw "<relpath>" <outfile>
    rel="${1:?relative path required (e.g. '/?op=download&capability=...')}"
    out="${2:?output file required}"
    mkdir -p "$(dirname "$out")"
    _curl "$HCTF_BASE$rel" -o "$out"
    printf 'saved %s\n' "$out" >&2
    ;;

  submit)
    ch="${1:?challenge id required}"; shift || true
    if [[ "${1:-}" == "--json" ]]; then
      ans=$(cat "${2:?json file required}")
    else
      ans='{}'
      for kv in "$@"; do
        [[ "$kv" == *=* ]] || die "answer must be id=value, got '$kv'"
        id="${kv%%=*}"; val="${kv#*=}"
        ans=$(jq -c --arg k "$id" --arg v "$val" '. + {($k):$v}' <<<"$ans")
      done
    fi
    body=$(jq -nc --arg ch "$ch" --argjson a "$ans" '{challenge:$ch, answers:$a}')
    _post "" "$body"
    ;;

  openapi)
    _get "?op=openapi"
    ;;

  ""|-h|--help|help)
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'
    ;;

  *)
    die "unknown command '$cmd' (try: gm.sh help)"
    ;;
esac
