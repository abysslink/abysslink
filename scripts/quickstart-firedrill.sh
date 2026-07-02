#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
#
# quickstart-firedrill.sh — LNCH-02 quickstart fire-drill harness.
#
# Times a new user walking the documented quickstart (docs/quickstart.md) and
# asserts each step. The LNCH-02 BLOCKING GATE requires an OUTSIDER to finish the
# quickstart in under 10 minutes on FRESH macOS + Ubuntu VMs. This harness makes
# that drill repeatable and measurable; it does NOT replace the human-on-fresh-VM
# requirement — it instruments it.
#
# Modes:
#   (default)   dry-run / read-only walkthrough — NO system mutation. Safe to run
#               anywhere (CI, dev box). Validates the binary, the dry-run `up` plan,
#               and `doctor`, and confirms the mutating commands exist + parse.
#   --apply     REAL operator flow for a THROWAWAY fresh VM only: runs
#               `init --yes`, `up --apply`, `doctor`, `enroll phone --apply`.
#               Mutates the system (Tailscale, SSH, sudo). Refuses unless
#               ABYSSLINK_FIREDRILL_I_UNDERSTAND=1 is set. Operator-only.
#
# Budget: LNCH-02 is < 10 min (600s). The harness prints elapsed per step and total,
# and FAILS the drill if the total exceeds the budget.
#
# Exit codes: 0 = drill passed within budget; 1 = a step failed or budget exceeded.

set -uo pipefail

BUDGET_SECONDS="${ABYSSLINK_FIREDRILL_BUDGET:-600}"
BIN="${ABYSSLINK_BIN:-./abysslink}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

# Portable monotonic-ish seconds (date +%s is fine for whole-second budgets).
now() { date +%s; }
START=$(now)
FAILS=0
STEP_N=0

# Per-run scratch files (mktemp, not predictable /tmp names) — the --apply drill
# runs as root, so a fixed /tmp path is a symlink-clobber vector (CWE-59/377) and
# breaks a second user on a shared box. Cleaned up on exit.
FD_OUT="$(mktemp "${TMPDIR:-/tmp}/firedrill.out.XXXXXX")"
FD_DOCTOR="$(mktemp "${TMPDIR:-/tmp}/firedrill.doctor.XXXXXX")"
trap 'rm -f "$FD_OUT" "$FD_DOCTOR"' EXIT INT TERM

say() { printf '%s\n' "$*"; }
hr() { printf '%s\n' "------------------------------------------------------------"; }

# run_step "label" budget_hint_seconds cmd...
run_step() {
  local label="$1"; shift
  # optional numeric budget-hint arg (informational, ignored) — drop if present
  if [ $# -gt 0 ] && printf '%s' "$1" | grep -Eq '^[0-9]+$'; then shift; fi
  STEP_N=$((STEP_N + 1))
  local t0 t1 rc
  t0=$(now)
  printf '[%d] %-46s ' "$STEP_N" "$label"
  if "$@" >"$FD_OUT" 2>&1; then rc=0; else rc=$?; fi
  t1=$(now)
  local dt=$((t1 - t0))
  if [ "$rc" -eq 0 ]; then
    printf 'OK   (%ds)\n' "$dt"
  else
    printf 'FAIL (%ds, exit %d)\n' "$dt" "$rc"
    say "      -> last output:"; sed 's/^/      | /' "$FD_OUT" | tail -6
    FAILS=$((FAILS + 1))
  fi
  return 0
}

# A check that an assertion holds (no timing emphasis), used for "command exists".
assert_contains() {
  local label="$1" needle="$2"; shift 2
  STEP_N=$((STEP_N + 1))
  printf '[%d] %-46s ' "$STEP_N" "$label"
  if "$@" 2>&1 | grep -q -- "$needle"; then
    printf 'OK\n'
  else
    printf 'FAIL (missing: %s)\n' "$needle"
    FAILS=$((FAILS + 1))
  fi
}

hr
say "Abysslink quickstart fire-drill (LNCH-02)"
say "Mode:   $([ $APPLY -eq 1 ] && echo 'APPLY (real, mutating — throwaway VM only)' || echo 'dry-run / read-only (safe)')"
say "Binary: $BIN"
say "Budget: ${BUDGET_SECONDS}s (LNCH-02 < 10 min)"
hr

# 0. Binary present (a fresh VM would install via curl|sh or go install first).
if [ ! -x "$BIN" ]; then
  if command -v abysslink >/dev/null 2>&1; then
    BIN="$(command -v abysslink)"
  else
    say "FATAL: abysslink binary not found at '$BIN' and not on PATH."
    say "On a fresh VM, install first:  curl -fsSL https://abysslink.dev/install.sh | sh"
    exit 1
  fi
fi

# 1. Version / smoke.
run_step "version smoke" 5 "$BIN" version

# 2. Read-only health snapshot (doctor is fail-closed; non-zero is informative,
#    not a harness failure — capture it but don't fail the drill on doctor verdict).
STEP_N=$((STEP_N + 1)); printf '[%d] %-46s ' "$STEP_N" "doctor --json (read-only health)"
t0=$(now); "$BIN" --json doctor >"$FD_DOCTOR" 2>/dev/null; t1=$(now)
if [ -s "$FD_DOCTOR" ]; then
  findings=$(grep -o '"severity"' "$FD_DOCTOR" | wc -l | tr -d ' ')
  printf 'OK   (%ds, %s findings)\n' "$((t1 - t0))" "$findings"
else
  printf 'WARN (%ds, no JSON — doctor may need a config; non-blocking here)\n' "$((t1 - t0))"
fi

if [ $APPLY -eq 0 ]; then
  # ---- DRY-RUN SLICE (safe) ----
  # 3. `up` dry-run plan (default — no --apply). The core "what would happen" step.
  run_step "up (dry-run plan, no mutation)" 30 "$BIN" up --dry-run

  # 4-6. Confirm the mutating quickstart commands exist + parse (without running them).
  assert_contains "cmd exists: up --apply"        "--apply" "$BIN" up --help
  assert_contains "cmd exists: enroll phone"      "phone"   "$BIN" enroll --help
  assert_contains "cmd exists: daemon enable"     "enable"  "$BIN" daemon --help
  assert_contains "init non-interactive (--yes)"  "--yes"   "$BIN" init --help
else
  # ---- REAL OPERATOR FLOW (mutating) — throwaway VM only ----
  if [ "${ABYSSLINK_FIREDRILL_I_UNDERSTAND:-0}" != "1" ]; then
    say ""
    say "REFUSING --apply: this mutates the system (Tailscale, SSH, sudo, FileVault check)."
    say "Run ONLY on a throwaway fresh VM, then set ABYSSLINK_FIREDRILL_I_UNDERSTAND=1."
    exit 1
  fi
  : "${ABYSSLINK_EMAIL:?--apply requires ABYSSLINK_EMAIL for non-interactive init}"
  run_step "init --yes (non-interactive)"  120 "$BIN" init --yes --email "$ABYSSLINK_EMAIL"
  run_step "up --apply (converge)"         300 "$BIN" up --apply --yes
  run_step "doctor (post-apply health)"     60 "$BIN" doctor
  run_step "enroll phone --apply"           60 "$BIN" enroll phone --apply --yes
fi

ELAPSED=$(( $(now) - START ))
hr
say "Steps run:     $STEP_N"
say "Failures:      $FAILS"
say "Total elapsed: ${ELAPSED}s  (budget ${BUDGET_SECONDS}s)"
OVER=0; [ "$ELAPSED" -gt "$BUDGET_SECONDS" ] && OVER=1
if [ "$FAILS" -eq 0 ] && [ "$OVER" -eq 0 ]; then
  say "RESULT: PASS (within budget)"
else
  [ "$OVER" -eq 1 ] && say "RESULT: FAIL — over the ${BUDGET_SECONDS}s budget"
  [ "$FAILS" -gt 0 ] && say "RESULT: FAIL — ${FAILS} step(s) failed"
fi
hr
if [ $APPLY -eq 0 ]; then
  say "NOTE: dry-run mode validates the harness + non-mutating path only."
  say "LNCH-02 still requires an OUTSIDER on FRESH macOS + Ubuntu VMs running"
  say "  ABYSSLINK_FIREDRILL_I_UNDERSTAND=1 ABYSSLINK_EMAIL=you@x scripts/quickstart-firedrill.sh --apply"
  say "and timing the real install->up->doctor->enroll flow under 10 minutes."
fi

[ "$FAILS" -eq 0 ] && [ "$OVER" -eq 0 ]
