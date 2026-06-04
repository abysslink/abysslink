---
phase: 26
slug: init-journey-gating-first-run-fixes
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-04
---

# Phase 26 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test (testify) |
| **Config file** | Makefile (`make lint test`) |
| **Quick run command** | `go test ./internal/cli/... ./internal/shell/...` |
| **Full suite command** | `make lint test` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/cli/... ./internal/shell/...`
- **After every plan wave:** Run `make lint test`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| shell.LookPath added | 26-01 | 1 | PHASE-26-B1 | T-26-01 | PATH probe only — no subprocess | unit | `go build ./internal/shell/...` | ✅ | ✅ green |
| openURL fixed | 26-01 | 1 | PHASE-26-B1 | T-26-01, T-26-02 | returns error when opener absent or non-zero exit; accepts shell.Runner param for mock injection | unit | `go test ./internal/cli/... -run TestOpenURL_NoOpenerError` | created in plan | ✅ green |
| checkACSleepDisabled fixed | 26-01 | 1 | PHASE-26-B3 | T-26-03 | >= 2 fields — annotated pmset output parses | unit | `go test ./internal/cli/... -run TestCheckACSleepDisabled -v` | created in plan | ✅ green |
| Stage 2 B2 fix | 26-02 | 2 | PHASE-26-B2 | T-26-04 | no sudo calls without real autoYes; output contains "Prerequisites verified." | unit | `go test ./internal/cli/... -run TestJourneyStage2_NoDuplicateCalls -v` | created in plan | ✅ green |
| Per-stage gates | 26-02 | 2 | PHASE-26-GATED-JOURNEY | T-26-05 | autoYes=true: no huh prompts; non-TTY: no hang | unit | `go test ./internal/cli/... -run TestRunJourney_AutoYes\|TestRunJourney_NonTTY -v` | updated+created | ✅ green |
| ACL stage | 26-02 | 2 | PHASE-26-ACL-STAGE | T-26-05, T-26-06 | headless: prints guidance, no RunInteractive | unit | `go test ./internal/cli/... -run TestJourneyStageCount\|TestJourneyStageLabels -v` | updated in plan | ✅ green |
| Stage count 8 | 26-02 | 2 | PHASE-26-ACL-STAGE | — | journeyLabels() == 8; journeyStages() == 8 | unit | `go test ./internal/cli/... -run TestJourneyStageCount\|TestJourneyStageLabels -v` | updated in plan | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements — `internal/cli` already has journey/init test files (`journey_test.go`, `cmd_init_headless_test.go`) with mock `shell.Runner` patterns. No new test framework setup required; all new tests are added inline to existing files.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Interactive stage gating (huh confirm prompts) | PHASE-26-GATED-JOURNEY | TTY interaction can't run in CI | Run `abysslink init` in a terminal; confirm each stage pauses and offers to run its command |
| Browser actually opens on macOS | PHASE-26-B1 | Requires GUI session (unit test covers error paths via mock runner; real open call requires display) | Run `abysslink init` on macOS; verify browser opens for Tailscale auth when user selects "No, open the link for me" |
| sudo credential cache reused across privileged calls | PHASE-26-SUDO-CACHE | Requires interactive macOS session with real sudo; cannot be mocked — tty-keyed timestamp reuse is a kernel/PAM behaviour | (1) On macOS with a fresh sudo timestamp, run `abysslink init --apply` in a terminal. (2) Observe that a sudo password prompt appears exactly once during the init run (for maybeFixFirewall or maybeFixSleep, whichever runs first). (3) Confirm the second privileged call completes without prompting again (sudo reuses the cached tty-keyed timestamp from the same controlling terminal). (4) If both calls produce separate prompts, the RunInteractive routing in cmd_init.go is not correctly forwarding the tty fd — re-examine the maybeFixFirewall/maybeFixSleep call sites. |

---

## Source Audit

| Source Type | Item | Covered By | Status |
|-------------|------|------------|--------|
| GOAL | Fix B1 openURL macOS probe false success | Plan 26-01 Task 1+2 | COVERED |
| GOAL | Fix B2 Stage 2 hardcoded autoYes=true | Plan 26-02 Task 1 | COVERED |
| GOAL | Fix B3 pmset parser exactly-2-field | Plan 26-01 Task 1+2 | COVERED |
| GOAL | Per-stage confirm gates | Plan 26-02 Task 1+2 | COVERED |
| GOAL | Stages 3–6 offer to run underlying command | Plan 26-02 Task 1 | COVERED |
| GOAL | New ACL stage | Plan 26-02 Task 1+2 | COVERED |
| GOAL | Headless paths unchanged (T-10-16) | Plan 26-02 Task 1+2 | COVERED |
| GOAL | --resume keeps working (8-stage count stable) | Plan 26-02 Task 1+2 | COVERED |
| GOAL | Reconcile "NON-BLOCKING" doc comment | Plan 26-02 Task 1 | COVERED |
| CONTEXT D-* | None — no locked D-XX decisions in CONTEXT.md | — | N/A |
| RESEARCH | shell.LookPath as package-level function (not Runner method) | Plan 26-01 Task 1 | COVERED |
| RESEARCH | Stage 2 convert to summary (no re-run pattern) | Plan 26-02 Task 1 | COVERED |
| RESEARCH | ACL stage uses runner.RunInteractive (not requireAdmin) | Plan 26-02 Task 1 | COVERED |

**No deferred ideas planned.** (Full Bubble Tea animated journey, ACL OAuth credential setup, and changes outside journey.go/cmd_init.go are scoped out per CONTEXT.md.)

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (no Wave 0 test-scaffold plan needed — existing test files used)
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-06-04

---

## Validation Audit 2026-06-04

| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 0 |
| Escalated | 0 |

All 7 mapped tests exist and pass (`TestOpenURL_NoOpenerError`, `TestCheckACSleepDisabled`, `TestJourneyStage2_NoDuplicateCalls`, `TestRunJourney_AutoYes`, `TestRunJourney_NonTTY`, `TestJourneyStageCount`, `TestJourneyStageLabels`). `go build ./internal/shell/...` OK. Quick suite `go test ./internal/cli/... ./internal/shell/...` green. No new tests generated — no auditor spawn required.
