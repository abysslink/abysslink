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

// Package gate provides the observe-only GatedRunner decorator around
// shell.Runner (D-38, D-39, D-40).
//
// Contract (v4.0.0, Phase 27): every Runner method records the exec — binary
// name, an argv sha256, and a D-39 closure sha256 (resolved binary path + cwd
// + length-prefixed argv + script content when args[0] names a readable
// regular file) — then delegates verbatim to the inner Runner. No retry, no
// mutation, no error wrapping, no behavior change. Raw argv is NEVER logged:
// arguments can carry user paths, hostnames, and tokens-by-accident, so the
// record carries hashes only (D-38, T-27-14).
//
// Phase 30 (APPR-01..05) flips this decorator to enforcing — approve/deny on
// the phone before the exec proceeds — without touching any module, because
// the interception point already exists at both composition roots
// (cmd/abysslinkd and internal/cli) and demonstrably sees every
// module/consumer exec (the live counter on daemon GET /status).
//
// D-40 (self-deadlock rule): the daemon keeps a structurally SEPARATE ungated
// Runner instance for its internal plumbing — watchers, probes, and the
// session registry — wired at the composition root. The bypass is visible in
// the dependency wiring and is not runtime-toggleable, so the Phase 30
// enforcing gate can never deadlock the daemon on its own execs.
package gate
