// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Abysslink Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package budget implements the Phase 31 agent kill-switch ("apoptosis"):
// budget observation (wall-clock threshold, loop detection via the GatedRunner
// closure-hash stream, and optional token tiers), the escalation ladder
// (shadow notify → SIGSTOP-then-ask → kill), and audit binding of the
// asciinema cast sha256 at run end (KILL-01..05).
//
// Shadow mode is the shipped default (D-05). The full escalation ladder
// (SIGSTOP → phone Resume/Kill via Phase-30 APPR loop → SIGKILL) is
// explicit opt-in via budget.ladder: true in abysslink.yaml.
//
// The observation-to-escalation flow:
//
//	Watcher.Watch(ctx, pgid, castPath, stashSHA, headSHA)
//	    ├─ wall-clock ticker: fires after Config.WallClock elapsed
//	    ├─ gate.Gated.SetObserver tap: closure-hash ring buffer → loop trip
//	    │
//	    ├─ shadow mode (Ladder:false): → SendAgentStopped(reason), no signal
//	    └─ ladder mode (Ladder:true):  → SIGSTOP → approve.Registry →
//	         approve: SIGCONT + re-arm
//	         deny:    SIGTERM → sleep(KillGrace) → SIGKILL
//	         timeout: stay frozen + re-notify (D-06: never auto-decide)
//	    │
//	    └─ on Watch return (ctx cancelled / process ended):
//	         audit.Append("arm-run:end", castPath, castBytes, false)
//
// Architecture constraints:
//   - This package MUST NEVER import internal/modules/claudecode. Budget is a
//     generic observer; Claude Code is one possible consumer of abysslink arm.
//     The D-01a two-part split places YAML validation in internal/modules/budget
//     and the runtime watcher engine here at internal/budget.
//   - Uses syscall.Kill (stdlib syscall) for signalling — NOT os/exec (CLAUDE.md
//     hard rule: only internal/shell may import os/exec).
//   - All signal errors are logged with slog.Warn; no panics in control flow.
//   - context.Context propagates through Watch to all blocking calls.
//
// Requirements: KILL-01 (observation), KILL-02 (escalation), KILL-05 (cast audit).
// Related: KILL-03 (pgid plumbing in internal/shell), KILL-04 (rollback in cmd_arm.go).
package budget
