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

// Package budget implements the install-time Detect/Plan/Apply/Verify config shim
// for the budget: YAML block (Phase 31, D-01a config-validation half of KILL-01).
//
// It validates budget thresholds (wall_clock_minutes, loop_n, kill_grace_seconds)
// and can write/update the budget: block in abysslink.yaml with shadow-mode
// defaults when the block is absent or invalid.
//
// This package handles config concerns ONLY. The runtime watcher engine (observation
// goroutine, escalation ladder, process-group signalling) lives at internal/budget
// (peer of internal/gate / internal/approve).
//
// This package must NEVER import internal/budget (the runtime watcher engine) or
// internal/modules/claudecode (D-01a: budget is a generic shim; Claude Code is one
// possible consumer of abysslink arm, not a core dependency).
package budget
