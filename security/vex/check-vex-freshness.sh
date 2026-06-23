#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
#
# check-vex-freshness.sh — enforce the 90-day validity window on hand-written
# OpenVEX statements.
#
# OpenVEX has no native expiry field, so the project convention (SUPL-03) is:
# every hand-written statement carries an ISO-8601 ".timestamp" and is considered
# stale once (now - timestamp) > 90 days. A stale statement is a silent-bypass
# risk (T-32-07): a finding it suppresses may since have become reachable. This
# script fails CI on any stale hand-written doc, forcing a re-review + re-stamp.
#
# Scope: ONLY hand-written statements in security/vex/*.openvex.json. The
# govulncheck-derived auto VEX (dist/govulncheck.openvex.json) is regenerated on
# every run, is therefore always fresh, and is NOT checked here. Fixtures under
# security/vex/testdata/ are deliberately stale-by-design suppression proofs and
# are excluded.
#
# Exit codes: 0 = all fresh (or none present); 1 = at least one stale doc;
# 2 = a precondition failed (jq missing, unparseable timestamp).

set -eu

VEX_DIR="$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)"
MAX_AGE_DAYS=90
MAX_AGE_SECONDS=$((MAX_AGE_DAYS * 24 * 60 * 60))

if ! command -v jq >/dev/null 2>&1; then
  echo "check-vex-freshness: jq is required but not found on PATH" >&2
  exit 2
fi

now_epoch="$(date -u +%s)"
stale=0
checked=0

# Iterate hand-written docs only. testdata/ fixtures are excluded by keeping the
# glob non-recursive (no -r / find).
for doc in "$VEX_DIR"/*.openvex.json; do
  # Guard the literal-glob case when no files match.
  [ -e "$doc" ] || continue
  checked=$((checked + 1))

  ts="$(jq -r '.timestamp // empty' "$doc")"
  if [ -z "$ts" ]; then
    echo "check-vex-freshness: $doc has no .timestamp field" >&2
    exit 2
  fi

  # Parse ISO-8601 to epoch. GNU date and BSD/macOS date differ; try GNU first,
  # then the BSD form. CI runs on Linux (GNU date) — the BSD branch is a local
  # developer convenience.
  if doc_epoch="$(date -u -d "$ts" +%s 2>/dev/null)"; then
    :
  elif doc_epoch="$(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$ts" +%s 2>/dev/null)"; then
    :
  else
    echo "check-vex-freshness: $doc has an unparseable .timestamp '$ts'" >&2
    exit 2
  fi

  age=$((now_epoch - doc_epoch))
  if [ "$age" -gt "$MAX_AGE_SECONDS" ]; then
    age_days=$((age / 86400))
    echo "STALE: $doc is ${age_days}d old (> ${MAX_AGE_DAYS}d). Re-review and re-stamp .timestamp." >&2
    stale=$((stale + 1))
  else
    age_days=$((age / 86400))
    echo "fresh: $(basename "$doc") (${age_days}d old)"
  fi
done

if [ "$checked" -eq 0 ]; then
  echo "check-vex-freshness: no hand-written security/vex/*.openvex.json found (nothing to check)"
  exit 0
fi

if [ "$stale" -gt 0 ]; then
  echo "check-vex-freshness: ${stale} stale hand-written VEX doc(s) — failing." >&2
  exit 1
fi

echo "check-vex-freshness: all ${checked} hand-written VEX doc(s) fresh."
exit 0
