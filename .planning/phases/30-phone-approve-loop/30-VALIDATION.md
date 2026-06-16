---
phase: 30
slug: phone-approve-loop
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-17
---

# Phase 30 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go `testing` package + `testify` (assert/require) |
| **Config file** | none — standard `go test ./...` |
| **Quick run command** | `go test ./internal/approve/... ./internal/gate/... ./internal/daemon/... ./internal/notifyv2/... -count=1 -race` |
| **Full suite command** | `make lint test` |
| **Estimated runtime** | ~30–60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/approve/... ./internal/gate/... ./internal/daemon/... -count=1 -race`
- **After every plan wave:** Run `make lint test`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 30-01-T1 | 01 | 1 | APPR-01, APPR-02, APPR-03, APPR-04 | T-30-01, T-30-02, T-30-05 | CAS resolve() called twice concurrently — only first returns true; no timeout/error path reaches Approved:true; HMAC sign/verify round-trips; Tier() force-upgrades critical | unit (tdd) | `go test ./internal/approve/... -count=1 -race -v 2>&1 \| tail -20` | ❌ W0 | ⬜ pending |
| 30-02-T1 | 02 | 2 | APPR-04 | T-30-07, T-30-08 | kindApprove/kindDeny tokens have distinct prefixes; cross-kind probe miss does not burn the alternate token; approve tokens evictable before bootstrap tokens | unit (tdd) | `go test ./internal/daemon/ -run TestMintApprove -run TestMintDeny -run TestDropOldest_Approve -run TestApproveExpiry -count=1 -race -v 2>&1 \| tail -20` | ❌ W0 | ⬜ pending |
| 30-02-T2 | 02 | 2 | APPR-02, APPR-03, APPR-04 | T-30-09, T-30-10, T-30-11, T-30-12, T-30-13 | GET /approve/{denyToken} returns 404 without burning deny token; expired token returns 404; valid approve → 200 + audit Append; handleApproveWait returns 408 on timeout; /status counters increment | unit (tdd) | `go test ./internal/daemon/ -run TestHandleApprove -run TestHandleDeny -run TestHandleApproveRequest -run TestHandleApproveWait -run TestApproveStatus -count=1 -race -v 2>&1 \| tail -30` | ❌ W0 | ⬜ pending |
| 30-03-T1 | 03 | 3 | APPR-01, APPR-05 | T-30-14, T-30-15, T-30-16 | Gated.Run with mismatched closure hash returns ErrClosureHashMismatch; no ApprovalToken → ErrApprovalRequired; shadow mode delegates verbatim; daemon-internal runner (plain New) never enters enforcing path | unit (tdd) | `go test ./internal/gate/... -count=1 -race -v 2>&1 \| tail -30` | ❌ W0 | ⬜ pending |
| 30-03-T2 | 03 | 3 | APPR-04 | T-30-17 | RenderedNote.Actions populated for KindApprovalRequest with Approve+Deny labels and URLs; non-approval messages have nil Actions; ntfy module compiles with X-Actions: header | unit | `go test ./internal/notifyv2/... -count=1 -race -v 2>&1 \| tail -20 && go build ./internal/modules/ntfy/... 2>&1` | ❌ W0 | ⬜ pending |
| 30-04-T1 | 04 | 4 | APPR-05 | T-30-22 | Gate.Enforcing defaults false; Approval.TimeoutSeconds defaults 120; timeout below floor 10 returns validation error; YAML extra_critical is appended not replaced | unit (tdd) | `go test ./internal/config/... -run TestDefaultConfig_Gate -run TestDefaultConfig_Approval -run TestValidate_Approval -count=1 -v 2>&1 \| tail -15` | ❌ W0 | ⬜ pending |
| 30-04-T2 | 04 | 4 | APPR-05, APPR-06 | T-30-19, T-30-20, T-30-21 | Apply() writes PreToolUse+PermissionRequest hooks when enforcing=true; idempotent on second Apply; --check exits 2 on deny / exits 0 on approve; --permission-request returns within 100ms with allow JSON; D-03 race: TTY goroutine and phone goroutine start concurrently, first answer wins via CAS, loser's Resolve returns false | unit (tdd) | `go test ./internal/modules/claudecode/... -run TestModule_PermissionRequestHook -run TestModule_HookIdempotent -run TestModule_NoCoupling -run TestApproveCheck -run TestApproveRace -count=1 -race -v 2>&1 \| tail -20 && go build ./cmd/abysslink/... 2>&1` | ❌ W0 | ⬜ pending |
| 30-05-T1 | 05 | 5 | APPR-06 | T-30-24, T-30-25 | No forbidden import in internal/approve (no claudecode/gate/daemon/modules); no claudecode import in internal/gate; AST test self-validates (adding a forbidden import causes test to fail) | static (ast) | `go test ./internal/approve/... ./internal/gate/... -run TestApprove_NoClaude -run TestGate_NoClaude -count=1 -v 2>&1 \| tail -15` | ❌ W0 | ⬜ pending |
| 30-05-T2 | 05 | 5 | APPR-01, APPR-02, APPR-03, APPR-04, APPR-05, APPR-06 | T-30-26 | make lint test exits 0; all APPR-01..06 named tests pass; no capability URL in slog calls; WithEnforcing not called in daemon-internal runner; zero golangci-lint findings | integration | `make lint test 2>&1 \| tail -30` | ✅ (make exists) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

All test files listed above are new (❌ W0). They are created by the task that implements them — no pre-existing test infrastructure is needed. The Go test framework and testify are already in go.mod.

The following test files must be created by their respective plans before execution:

- [ ] `internal/approve/registry_test.go` — CAS, timeout, headless deny, concurrent, critical-tier, late-approve tests (Plan 01 Task 1)
- [ ] `internal/approve/hmac_test.go` — HMAC round-trip, action mismatch, constant-time (Plan 01 Task 1)
- [ ] `internal/daemon/content_internal_test.go` — extend with TestMintApprove, TestMintDeny, TestDropOldest_Approve, TestApproveExpiry (Plan 02 Task 1)
- [ ] `internal/daemon/content_server_internal_test.go` — extend with TestHandleApprove_*, TestHandleDeny_*, TestHandleApproveRequest_*, TestHandleApproveWait_*, TestApproveStatus_* (Plan 02 Task 2)
- [ ] `internal/gate/gate_test.go` — extend with TestGated_ShadowMode, TestGated_EnforcingNoToken, TestGated_ClosureHashMismatch, TestGated_ClosureHashMatch, TestGated_InternalBypass, TestGated_TokenInContext (Plan 03 Task 1)

*Existing infrastructure covers the remaining requirements (make, golangci-lint, testify already in go.mod).*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Phone receives ntfy Approve/Deny buttons and tapping Approve resolves the pending request | APPR-04, D-15 | Requires a real phone with ntfy app and a live tailnet | 1. Run `abysslink up --apply` with gate.enforcing=true. 2. Trigger a gated exec from the CLI. 3. Check ntfy app on phone for the approval notification. 4. Tap "Approve". 5. Verify CLI unblocks with exit 0. |
| Pushcut / Apple Watch tap resolves the request | D-15 (documented recipe) | Requires Pushcut app + Apple Watch | Follow the documented recipe in docs/ against the same GET capability-URL contract |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify commands (real commands from each plan's `<verify>` block)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (every task has a verify command)
- [x] Wave 0 covers all MISSING references (all new test files are created by the implementing task)
- [x] No watch-mode flags (all commands use `-count=1`, no `-watch`)
- [x] Feedback latency < 60s (per-task commands run in < 30s; make lint test runs in < 60s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved
