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

// Package quorum implements the E4.1 quorum-sensing action gate: a monotone
// security lattice DENY > ESCALATE > ALLOW combined by the meet
// (most-restrictive-wins) over four deterministic verifiers that are
// independent in INPUT SIGNAL:
//
//	V1 syntactic      — the raw argv token stream, nothing else.
//	V2 policy         — a parsed intent model evaluated against protected
//	                    paths/branches policy.
//	V3 behavior       — time and history only (in-memory RecordExec ring +
//	                    optional spend signal).
//	V4 reversibility  — filesystem and VCS world state via read-only probes.
//
// It is a peer of internal/gate, internal/approve, and internal/budget — gate
// policy, NOT a modules.Module (no Detect/Plan/Apply lifecycle).
//
// Invariants (violating any is a security regression):
//
//   - One DENY is a veto no consensus can overturn. ALLOW requires the absence
//     of any DENY plus unanimous *confident* ALLOW — never a majority.
//   - Verifier error, timeout, panic, and abstention fail CLOSED: they map to
//     ESCALATE (or, at stage 0, to DENY), never to ALLOW.
//   - A compiled-in deny-floor (Funnel, disk-encryption disable, audit-log
//     destruction, Tailnet-Lock disable, ntfy 0.0.0.0 bind, canary tripwires)
//     is evaluated before the lattice and before any approval token. No YAML
//     key exists to remove or disable it (the Funnel-omission pattern).
//   - No LLM and no network call participate in the decision path; verifiers
//     are pure Go rules over distinct input signals (enforced by the
//     go/parser source-invariant tests in invariants_test.go).
//   - Configuration is tighten-only: add-only lists, floor/ceiling-checked
//     numerics, raise-only tier overrides (D-08 / Funnel-omission patterns).
//   - Every decision — enforcing AND shadow — is audited as a full vote
//     vector. Raw argv, env, stdin, full paths, and capability URLs never
//     appear in audit content, logs, or approval notifications (D-38,
//     T-27-14, C-03/C-09).
package quorum
