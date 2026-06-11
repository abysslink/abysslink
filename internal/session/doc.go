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

// Package session maintains the daemon-side registry of live tmux
// sessions, windows, and panes (BACK-03). Hard rules:
//
//   - IDs route, names display (SPEC §3.1): routing happens only on the
//     stable $n/@n/%n identifiers; session/window/pane names are free text
//     and may be attacker-chosen — they never influence routing fields.
//   - Events trigger polls, polls write state: tmux control-mode
//     notifications never mutate registry state directly — they only
//     schedule a list-panes re-poll, which is the single source of truth
//     (single writer).
//   - The registry receives the PLAIN (ungated) shell.Runner (D-40): its
//     tmux plumbing is daemon-internal and structurally bypasses the
//     GatedRunner so the registry can never observe — or in Phase 30,
//     deadlock on — its own execs.
package session
