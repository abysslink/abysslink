#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
#
# claims-check.sh — warns on unresolved security-claim pointers in CLAIMS-AUDIT.md.
#
# CLAIMS-AUDIT.md is the ground truth — a Markdown table where every row maps a
# security claim to a code file path or doctor-check ID. This script validates that
# (1) every claim row has a non-empty, non-TODO pointer and (2) every file-path pointer
# exists on disk. Doctor-check IDs (no slash, e.g. "doctor:disk-encryption") are
# accepted as-is without a disk check — they reference runtime checks, not source
# files.
#
# Scope: reads CLAIMS-AUDIT.md (or the path given as $1); validates column-4 pointers
# only. Free-text prose is not scanned for security sentences — the human author is
# responsible for keeping the register complete.
#
# Exit codes: 0 = done (always — this check is NON-BLOCKING by locked decision D-01).

set -euo pipefail

CLAIMS_FILE="${1:-CLAIMS-AUDIT.md}"
WARN=0
ROW=0

if [[ ! -f "$CLAIMS_FILE" ]]; then
  echo "claims-check: WARN: $CLAIMS_FILE not found" >&2
  WARN=$((WARN + 1))
  echo "claims-check: done (exit 0, non-blocking)"
  exit 0
fi

while IFS='|' read -r _ num _claim _source pointer _status _; do
  # Skip header rows, separator rows, and blank lines
  # A data row has a claim ID in column 2 (e.g. "C-01", " C-01 ", etc.)
  [[ "$num" =~ ^[[:space:]]*C-[0-9]+ ]] || continue

  ROW=$((ROW + 1))
  claim_id="$(echo "$num" | tr -d ' \t')"

  # Strip leading/trailing whitespace from pointer field
  raw_pointer="$(echo "$pointer" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

  # Strip backticks
  raw_pointer="${raw_pointer//\`/}"

  if [[ -z "$raw_pointer" || "$raw_pointer" == "TODO" ]]; then
    echo "claims-check: WARN: claim ${claim_id} has no pointer" >&2
    WARN=$((WARN + 1))
    continue
  fi

  # Handle compound pointers joined by " + " — check each component
  IFS=' + ' read -ra components <<< "$raw_pointer"
  for component in "${components[@]}"; do
    component="$(echo "$component" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$component" ]] && continue

    # Extract file path — portion before first ':' (strips line numbers like file.go:42)
    filepath="${component%%:*}"

    # If the extracted portion contains a '/' it is a file path — stat-check it.
    # Bare doctor-check IDs (e.g. "doctor:disk-encryption") contain no slash and
    # are accepted without a disk check.
    if [[ "$filepath" == *"/"* ]]; then
      if [[ ! -f "$filepath" ]]; then
        echo "claims-check: WARN: claim ${claim_id} pointer '$filepath' not found on disk" >&2
        WARN=$((WARN + 1))
      fi
    fi
  done
done < "$CLAIMS_FILE"

if [[ $WARN -gt 0 ]]; then
  echo "claims-check: $WARN warning(s) — review CLAIMS-AUDIT.md" >&2
fi
echo "claims-check: done (exit 0, non-blocking)"
exit 0
