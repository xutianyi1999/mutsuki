#!/bin/bash
# Convert geolocation-cn.txt (V2Fly domain-list format) to adblock rules.
#
# Domains in the list → @@||domain^  exception rules → direct (no proxy)
# Domains NOT in the list → '||' catch-all blocking rule → via upstream proxy
#
# Compatible with the existing mutsuki adblock engine (no code changes needed).
# The '||' rule matches all domains; @@ exception rules override for cn domains.
#
# Usage: ./gen_cn_adblock.sh <geolocation-cn.txt> [output_file]
#   If output_file is omitted, prints to stdout.

set -euo pipefail

INPUT="${1:?Usage: $0 <geolocation-cn.txt> [output_file]}"
OUTPUT="${2:-}"

[[ -f "$INPUT" ]] || { echo "Error: file not found: $INPUT" >&2; exit 1; }

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

warn() { echo "  [warn] $*" >&2; }

{
  echo "! Generated from $(basename "$INPUT")"
  echo "! Format: adblock (compatible with mutsuki / adblock crate)"
  echo "! Domains in this list: direct connection (no proxy)"
  echo "! All other domains: via upstream proxy"
  echo "!"

  # Preprocess: strip BOM+CR, strip inline comments, drop blank/comment lines.
  # Single sed (never fails → no pipefail issue).
  sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' \
      -e 's/[[:space:]]*#.*$//' \
      -e '/^\s*$/d' \
      -e '/^[#!;]/d' \
      "$INPUT" \
    | while IFS= read -r line; do

    # Strip leading/trailing whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue

    prefix="${line%%:*}"
    rest="${line#*:}"

    # Trim whitespace on prefix and rest
    prefix="${prefix#"${prefix%%[![:space:]]*}"}"
    prefix="${prefix%"${prefix##*[![:space:]]}"}"
    rest="${rest#"${rest%%[![:space:]]*}"}"
    rest="${rest%"${rest##*[![:space:]]}"}"

    # No colon (or empty prefix) → treat whole line as domain
    if [[ "$rest" == "$line" || -z "$prefix" ]]; then
      echo "@@||${line}^"
      continue
    fi

    # Skip empty value
    [[ -z "$rest" ]] && continue

    case "$prefix" in
      domain)
        # Strip annotation suffix like '@cn', '@!cn'
        rest="${rest%@*}"
        rest="${rest%"${rest##*[![:space:]]}"}"
        echo "@@||${rest}^"
        ;;
      full)
        rest="${rest%@*}"
        rest="${rest%"${rest##*[![:space:]]}"}"
        echo "@@||${rest}^"
        ;;
      keyword|include)
        echo "@@${rest}"
        ;;
      regexp)
        warn "regexp entry skipped (adblock regex matches full URL, not bare domain). Line: $line"
        ;;
      *)
        warn "unknown prefix '${prefix}', treating as domain. Line: $line"
        echo "@@||${line}^"
        ;;
    esac
  done | sort -u

  echo "!"
  echo "! Catch-all: proxy everything not excepted above"
  echo "||"
} > "$TMP"

if [[ -n "$OUTPUT" ]]; then
  cp "$TMP" "$OUTPUT"
  echo "Written: $OUTPUT ($(wc -l < "$TMP") lines, $(grep -c '^@@' "$TMP") exception rules)" >&2
else
  cat "$TMP"
fi
