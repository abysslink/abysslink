---
phase: 26
slug: init-journey-gating-first-run-fixes
status: planned
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
| shell.LookPath added | 26-01 | 1 | PHASE-26-B1 | T-26-01 | PATH probe only — no subprocess | unit | `go build ./internal/shell/...` | ✅ | ⬜ pending |
| openURL fixed | 26-01 | 1 | PHASE-26-B1 | T-26-01, T-26-02 | returns error when opener absent or non-zero exit | unit | `go test ./internal/cli/... -run TestOpenURL` | created in plan | ⬜ pending |
| checkACSleepDisabled fixed | 26-01 | 1 | PHASE-26-B3 | T-26-03 | >= 2 fields — annotated pmset output parses | unit | `go test ./internal/cli/... -run TestCheckACSleepDisabled -v` | created in plan | ⬜ pending |
| Stage 2 B2 fix | 26-02 | 2 | PHASE-26-B2 | T-26-04 | no sudo calls without real autoYes | unit | `go test ./internal/cli/... -run TestJourneyStage2_NoDuplicateCalls -v` | created in plan | ⬜ pending |
| Per-stage gates | 26-02 | 2 | PHASE-26-GATED-JOURNEY | T-26-05 | autoYes=true: no huh prompts; non-TTY: no hang | unit | `go test ./internal/cli/... -run TestRunJourney_AutoYes\|TestRunJourney_NonTTY -v` | updated+created | ⬜ pending |
| ACL stage | 26-02 | 2 | PHASE-26-ACL-STAGE | T-26-05, T-26-06 | headless: prints guidance, no RunInteractive | unit | `go test ./internal/cli/... -run TestJourneyStageCount\|TestJourneyStageLabels -v` | updated in plan | ⬜ pending |
| Stage count 8 | 26-02 | 2 | PHASE-26-ACL-STAGE | — | journeyLabels() == 8; journeyStages() == 8 | unit | `go test ./internal/cli/... -run TestJourneyStageCount\|TestJourneyStageLabels -v` | updated in plan | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements — `internal/cli` already has journey/init test files (`journey_test.go`, `cmd_init_headless_test.go`) with mock `shell.Runner` patterns. No new test framework setup required; all new tests are added inline to existing files.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Interactive stage gating (huh confirm prompts) | PHASE-26-GATED-JOURNEY | TTY interaction can't run in CI | Run `abysslink init` in a terminal; confirm each stage pauses and offers to run its command |
| Browser actually opens on macOS | PHASE-26-B1 | Requires GUI session | Run `abysslink init` on macOS; verify browser opens for Tailscale auth when user selects "No, open the link for me" |

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

**Approval:** planned
