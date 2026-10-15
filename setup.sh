#!/usr/bin/env bash
#
# setup.sh — install the metadata-forensics toolchain and create the private
# Game Master auth config. Safe to re-run.
#
# Usage:
#     ./setup.sh            # install tools, then prompt for the GM token
#     ./setup.sh --deps     # install tools only
#     ./setup.sh --auth     # create/replace the auth config only
#
set -euo pipefail

AUTH_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hctf"
AUTH_FILE="$AUTH_DIR/auth.conf"

install_deps() {
  echo "== installing system packages (needs sudo) =="
  sudo apt-get update -qq
  sudo apt-get install -y -qq \
    libimage-exiftool-perl \
    p7zip-full \
    xxd \
    mediainfo \
    msitools \
    unzip poppler-utils imagemagick jq curl
  echo "== installing python deps =="
  # IMPORTANT: the toolkit runs the solver as `python3 -I` (isolated mode) so it
  # never imports code from the untrusted artifact tree. `-I` also disables the
  # per-user site (`~/.local/...`), so a `--user` install would be invisible at
  # solve time and dnfile/LnkParse3 fields would silently return null. Install
  # into the global site that `-I` *does* search, so `python3 -I` can import them.
  SITE="$(python3 -I - <<'PY'
import sys
# first global dist/site-packages on the isolated path
print(next(p for p in sys.path if p.endswith(('dist-packages', 'site-packages'))))
PY
)"
  python3 -m pip install -q --break-system-packages --target "$SITE" --upgrade dnfile LnkParse3 \
    || python3 -m pip install -q --target "$SITE" --upgrade dnfile LnkParse3
  echo "== versions =="
  exiftool -ver; msiinfo --version | head -1
  # verify under the SAME isolated mode the solver uses, not a plain interpreter
  python3 -I -c 'import dnfile, LnkParse3; print("dnfile", dnfile.__version__, "+ LnkParse3 importable under -I")'
}

create_auth() {
  mkdir -p "$AUTH_DIR"
  umask 077
  # Read the token without echoing it or placing it in argv/history.
  read -rsp 'Game Master token (gm1.<id>.<secret>): ' TOKEN; printf '\n'
  [[ "$TOKEN" =~ ^gm1\.[a-f0-9]{32}\.[a-f0-9]{64}$ ]] || {
    echo "warning: token does not match the gm1.<32hex>.<64hex> shape" >&2; }
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$AUTH_FILE"
  unset TOKEN
  chmod 600 "$AUTH_FILE"
  echo "wrote $AUTH_FILE (mode 600)"
  echo "export HCTF_AUTH=$AUTH_FILE   # add to your shell rc, or rely on the default path"
}

case "${1:-all}" in
  --deps) install_deps ;;
  --auth) create_auth ;;
  all)    install_deps; create_auth ;;
  *) echo "usage: setup.sh [--deps|--auth]" >&2; exit 1 ;;
esac

echo
echo "done. Sanity check:  HCTF_AUTH=$AUTH_FILE bin/gm.sh ls metadata-forensics"
