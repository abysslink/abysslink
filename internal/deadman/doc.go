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

// Package deadman implements the SUPL-06 dead-man switch foundation: a
// persistent, audit-written registry of armed runs (pgid + closure hash) and a
// lockdown action that disarms every registered pgid by reusing the Phase 31
// process-group kill ladder, revokes further agent autonomy, and audit-logs the
// event.
//
// The registry is the missing piece research flagged: today `abysslink arm`
// runs in-process and the budget Watcher only knows its own pgid, so no separate
// process can discover armed runs to disarm them. This package records every
// armed pgid in a state file under XDG_STATE_HOME/abysslink/armed-runs.json,
// written through the tamper-evident audit chain (never a bare os.WriteFile), so
// a separate process — the daemon-hosted dead-man timer (Plan 06) — can read it
// and disarm.
//
// Scope discipline (SUPL-06, locked in 32-CONTEXT.md): lockdown does disarm +
// revoke-autonomy + audit ONLY. It never touches the SSH CA, device
// credentials, or the network — that is too destructive for an automated timer.
// This package is deliberately generic: it carries no Claude-specific logic.
package deadman
