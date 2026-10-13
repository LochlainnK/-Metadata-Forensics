#!/usr/bin/env bash
#
# dig.sh — one-shot metadata triage for a file or a directory of evidence.
#
# Runs the standard metadata-forensics toolchain and the structural extractor
# so you can eyeball everything about an artifact at once. Use it to explore a
# NEW challenge type before teaching fmtprobe.py a new field.
#
# Usage:
#     dig.sh <file>              triage one file
#     dig.sh <dir>               triage every regular file under <dir>
#     dig.sh <archive.zip>       list + triage members (extracts to a temp dir)
#
# Treats inputs as untrusted data: never executes them, only inspects bytes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FMTPROBE="$HERE/fmtprobe.py"

have() { command -v "$1" >/dev/null 2>&1; }

triage_file() {
  local f="$1"
  echo "════════════════════════════════════════════════════════════════"
  echo "FILE: $f"
  echo "────────────────────────────────────────────────────────────────"
  echo "• type   : $(file -b "$f")"
  printf '• size   : %s bytes\n' "$(stat -c %s "$f" 2>/dev/null || wc -c <"$f")"
  echo "• digests:"
  printf '    md5    %s\n' "$(md5sum "$f" | cut -d' ' -f1)"
  printf '    sha1   %s\n' "$(sha1sum "$f" | cut -d' ' -f1)"
  printf '    sha256 %s\n' "$(sha256sum "$f" | cut -d' ' -f1)"
  echo "• first 32 bytes:"
  xxd -l 32 "$f" | sed 's/^/    /'

  echo "• fmtprobe structural fields:"
  python3 -I "$FMTPROBE" "$f" 2>/dev/null | sed 's/^/    /' || echo "    (none)"

  if have exiftool; then
    echo "• exiftool:"
    exiftool -a -G1 -s "$f" 2>/dev/null | grep -vE '^\[System\]|^\[ExifTool\]' | sed 's/^/    /' || true
  fi

  case "$(file -b --mime-type "$f")" in
    application/zip|application/java-archive)
      echo "• zip members (central-directory order):"
      7z l -ba "$f" 2>/dev/null | sed 's/^/    /' || unzip -l "$f" | sed 's/^/    /'
      ;;
    application/x-msi|application/x-ole-storage)
      if have msiinfo; then
        echo "• MSI streams:"; msiinfo list "$f" 2>/dev/null | sed 's/^/    /' || true
        echo "• MSI Property table:"; msiinfo export "$f" Property 2>/dev/null | sed 's/^/    /' || true
      fi
      ;;
    application/pdf)
      have pdfinfo && { echo "• pdfinfo:"; pdfinfo "$f" 2>/dev/null | sed 's/^/    /'; }
      ;;
  esac

  echo "• printable strings (first 20, len>=6):"
  strings -n 6 "$f" | head -20 | sed 's/^/    /'
  echo
}

main() {
  local target="${1:?usage: dig.sh <file|dir|archive.zip>}"
  if [[ -d "$target" ]]; then
    find "$target" -type f | sort | while read -r f; do triage_file "$f"; done
  elif [[ -f "$target" ]]; then
    if [[ "$(file -b --mime-type "$target")" == application/zip ]]; then
      local tmp; tmp="$(mktemp -d)"
      echo "# extracting $target -> $tmp"
      unzip -o -q "$target" -d "$tmp"
      triage_file "$target"      # the archive itself (zip.* fields)
      find "$tmp" -type f | sort | while read -r f; do triage_file "$f"; done
      rm -rf "$tmp"
    else
      triage_file "$target"
    fi
  else
    echo "dig.sh: not found: $target" >&2; exit 1
  fi
}
main "$@"
