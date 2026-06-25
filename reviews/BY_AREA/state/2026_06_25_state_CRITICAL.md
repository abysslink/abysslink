# TUI Review — area `state` — 2026-06-25

## Executive Summary
6 findings. Severity: CRITICAL 1, HIGH 1, MEDIUM 3, LOW 1. Buckets: AUTO_FIXABLE 0, FLOW_FIX 0, LOG 6.

## Risk Assessment
Status **CRITICAL**.

## Findings
#### T-007 — [CRITICAL/LOG] `internal/flow/steps.go:154` (state-feedback)

- **Problem:** StepConverge, StepLock, StepVerify, and StepACL each build a huh.Confirm bound to a local `runNow bool` (steps.go:155,177,245,265) that is immediately discarded (`_ = runNow` at :169,189,257,277). The documented contract says 'the caller reads the form result and invokes the command if the user confirmed', and FlowState even declares StageConvergeDone/StageLockDone/StageVerifyDone/StageACLDone fields 'Set to true by each step after the form is accepted'. But the caller runFlowStep (internal/cli/cmd_init.go:275-306) only runs the form and calls flow.WriteFlowState(i+1) — it never inspects the confirm value, and grep confirms StageXxxDone is never assigned or read anywhere. So when the user picks 'Yes, run it', NOTHING runs: no `abysslink up --apply`, no `lock init`, no `doctor`, no `acl push`, and no success/feedback message of any kind.
- **Impact:** The user is asked four affirmative-action questions during first-run setup ('Run `abysslink up --apply` now?', 'Run `abysslink lock init --apply` now?', etc.), enthusiastically answers Yes, and the wizard silently advances to the next stage with zero output. The user reasonably believes their system was converged, Tailnet Lock was enabled, and doctor passed — when in reality none of it happened. This is a silent no-op masquerading as success across the most security-critical setup stages (the user thinks Tailnet Lock is on when it is off).
- **Before (rendered):** A bordered huh confirm prompt reading 'Run `abysslink up --apply` now? — Converges your system to match abysslink.yaml.' with [Yes, run it] highlighted. After Enter the screen instantly shows the next stage's prompt ('Run `abysslink lock init --apply` now?') — no spinner, no 'Applying…' line, no '✓ done', no error, no acknowledgment that the previous Yes was acted on.
- **Fix:** Either (a) actually wire the result: change StepFunc/state so each step writes its confirm into FlowState (state.StageConvergeDone = runNow), have runFlowStep read it after RunWithContext, and on true invoke the corresponding command (newUpCmd's converge, lock init, doctor, acl push) with live feedback and a success/failure line; or (b) if execution is intentionally deferred to v2, change the prompt copy so it does not promise to 'run it now' — make these informational Notes ('Next, run `abysslink up --apply`') instead of affirmative Confirms, so the UI never claims an action it does not perform.
- **Confidence:** high  ·  verify 2/2

#### T-009 — [HIGH/LOG] `internal/flow/steps.go:176` (dead-handlers)

- **Problem:** flow.StepLock builds a huh.Confirm ("Yes, run it" / "No, I'll run it later") bound to a local `runNow` that is discarded at steps.go:189 (`_ = runNow`). The caller runFlowStep (cmd_init.go:275-306) never reads this result and never invokes `abysslink lock init --apply`. Non-reachability proof: the only consumers of the form in runFlowStep are the i==0 Backend/OAuth branches; there is no Stage-3 branch, and StageLockDone (state.go:78) has zero readers/writers in the repo.
- **Impact:** Tailnet Lock is a security-critical default (CLAUDE.md: 'Tailnet Lock is on by default'). The wizard prompts the user to enable it and, on Yes, does nothing — Tailnet Lock is never initialized and the disablement secrets are never printed. The user is left believing Lock is on when it is not, weakening the security posture the guide mandates.
- **Before (rendered):** Stage 3 shows 'Run `abysslink lock init --apply` now?' warning that disablement secrets print once; choosing 'Yes, run it' produces no SecretBox, no secrets, and jumps to Stage 4 — Tailnet Lock remains uninitialized.
- **Fix:** Wire the confirm result through to the caller and, on confirm, run the lock-init flow (which already exists as cmd_lock.go) so disablement secrets are actually rendered via tui.SecretBox. If wiring is out of scope, drop the interactive confirm and replace with a directive Note pointing at `abysslink lock init --apply`.
- **Confidence:** high  ·  verify 2/2

#### T-033 — [MEDIUM/LOG] `internal/flow/steps.go:244` (dead-handlers)

- **Problem:** flow.StepVerify builds a huh.Confirm bound to a local `runNow` discarded at steps.go:257. runFlowStep (cmd_init.go:275-306) never reads it and never runs `abysslink doctor`. Non-reachability proof: no Stage-5 branch exists in runFlowStep; StageVerifyDone (state.go:80) is defined but never written or read anywhere (grep across repo returns only the struct definition).
- **Impact:** User selects 'Yes, run it' expecting a health check during setup; nothing runs. No verification of the just-configured modules is performed, defeating the purpose of the Verify stage. Silent no-op gives false confidence that the setup was validated.
- **Before (rendered):** Stage 5 shows 'Run `abysslink doctor` now?'; pressing Yes shows no findings report, no exit-code output, and advances to Stage 6 — doctor never executes.
- **Fix:** Branch on the confirm result in runFlowStep and invoke the doctor command when confirmed, or replace the confirm with a Note instructing the user to run `abysslink doctor`.
- **Confidence:** high  ·  verify None/0

#### T-034 — [MEDIUM/LOG] `internal/flow/steps.go:264` (dead-handlers)

- **Problem:** flow.StepACL builds a huh.Confirm ("Yes, push ACL" / "No, I'll manage it manually") bound to a local `runNow` discarded at steps.go:277. runFlowStep never reads it and never invokes `abysslink acl push --apply`. Non-reachability proof: no Stage-6 branch in runFlowStep (cmd_init.go:275-306); StageACLDone (state.go:81) has no writers/readers repo-wide.
- **Impact:** User selects 'Yes, push ACL' and the abysslink ACL is never pushed to the tailnet — the network policy the wizard promised to apply is silently skipped. A no-op action on a confirm the user explicitly approved.
- **Before (rendered):** Stage 6 shows 'Run `abysslink acl push --apply` now?'; choosing 'Yes, push ACL' yields no push output and advances to the Done summary — no ACL is sent to the tailnet.
- **Fix:** Wire the confirm result to the caller and invoke the acl push command when confirmed, or convert the confirm into a Note that directs the user to `abysslink acl push --apply`.
- **Confidence:** high  ·  verify None/0

#### T-042 — [MEDIUM/LOG] `internal/flow/steps.go:154` (error-paths)

- **Problem:** StepConverge (line 154), StepLock (176), StepVerify (244) and StepACL (264) each build a huh.NewConfirm bound to a function-local `var runNow bool`, then explicitly throw it away: `_ = state` / `_ = runNow` (e.g. lines 168-169). Their doc comments say 'the caller reads the form result and invokes the command if the user confirmed', but the caller runFlowStep (cmd_init.go:275-306) does NOT read any result — it just runs the form and advances the stage. The FlowState.StageConvergeDone/StageLockDone/StageVerifyDone/StageACLDone fields (state.go:75-81) are never written by anyone either. So when the user answers 'Yes, run it' to 'Run `abysslink up --apply` now?' / 'Run `abysslink lock init --apply` now?' / 'Run `abysslink doctor` now?' / 'Run `abysslink acl push --apply` now?', NOTHING happens — the confirmed action is silently dropped and the wizard moves on.
- **Impact:** Four wizard stages present an actionable Yes/No, the user says Yes, and the promised command never runs. The user finishes init believing converge / Tailnet-Lock-init / doctor / acl-push happened when none did. For Tailnet Lock specifically this is a security-relevant false sense of completion (the user thinks Lock is enabled). This is an error-of-omission in the control flow: a collected user intent that is unconditionally swallowed.
- **Before (rendered):** Wizard shows 'Run `abysslink lock init --apply` now?  [Yes, run it]'. User selects Yes and presses Enter. The next stage's form appears immediately; no lock-init output, no disablement-secret box, no 'running...' spinner. The user later runs `abysslink lock status` and finds Lock is still disabled.
- **Fix:** Either (a) wire the result through: store the confirm into a state field the step sets (e.g. state.StageConvergeDone = runNow via a pointer the form writes, mirroring StepEnroll's Validate-side persistence at steps.go:234), and have runFlowStep act on it (shell out to the corresponding command through internal/shell.Runner / the relevant cli helper) — respecting --dry-run defaults and the IO boundary; or (b) if running sub-commands from inside init is out of scope, change the copy so the steps are pure 'next step' notes, not Yes/No confirms that imply action. Do not ship a confirm whose answer is discarded.
- **Confidence:** high  ·  verify None/0

#### T-035 — [LOW/LOG] `internal/flow/state.go:73` (dead-handlers)

- **Problem:** The FlowState struct declares seven per-stage completion booleans (StageAccountDone, StagePrereqsDone, StageConvergeDone, StageLockDone, StageEnrollDone, StageVerifyDone, StageACLDone) with a doc comment saying 'Set to true by each step after the form is accepted ... caller calls WriteFlowState after setting these.' Repo-wide grep shows these fields are NEVER written and NEVER read — the only reference outside state.go is a comment at steps.go:168 ('state.StageConvergeDone will be set by the caller after form execution') describing wiring that does not exist. Resume tracking actually uses a separate integer last_stage written by flow.WriteFlowState (state.go:108) keyed off the loop index, not these flags.
- **Impact:** Dead struct fields documented as load-bearing state that no code path exercises. They mislead maintainers into thinking stage-completion is tracked via FlowState (it is not), and they are the unbuilt sink the confirm-step no-ops were supposed to feed (steps.go:168). Low runtime impact but cements the broken contract behind the dead confirm handlers above.
- **Before (rendered):** N/A (internal state) — these flags would, if wired, gate whether each stage's command had run; instead they stay false forever regardless of user choices.
- **Fix:** Either delete the seven StageXxxDone fields (and the stale comment at steps.go:168) since the integer last_stage already drives resume, or actually wire them: have each step set its flag on confirm and have runFlowStep act on / persist them.
- **Confidence:** high  ·  verify None/0

## Checklist
- [ ] T-007 (CRITICAL/LOG) internal/flow/steps.go:154
- [ ] T-009 (HIGH/LOG) internal/flow/steps.go:176
- [ ] T-033 (MEDIUM/LOG) internal/flow/steps.go:244
- [ ] T-034 (MEDIUM/LOG) internal/flow/steps.go:264
- [ ] T-042 (MEDIUM/LOG) internal/flow/steps.go:154
- [ ] T-035 (LOW/LOG) internal/flow/state.go:73