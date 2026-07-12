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

// Package duress implements the Phase 39 duress-decoy (DUR-01..03).
//
// THREAT MODEL — CASUAL COERCION ONLY. The decoy defends against the
// shoulder-glance, the border-guard "show me", the roommate who grabs the
// terminal: you enter the DECOY credential instead of your real one and are
// shown a benign, plausible rig view (a quiet machine with no fleet and no live
// sessions) while your real session is degraded for real in the background. The
// honest value is measured in seconds-to-minutes. It is NOT plausible
// deniability against a forensic adversary: the abysslink.yaml on disk carries a
// duress stanza, so anyone who images the disk learns the feature exists and
// (from state/audit/backups) that a real fleet was present. We claim nothing
// against that adversary — full-disk encryption is the real at-rest control.
//
// NON-DESTRUCTIVE BY DESIGN AND BY TEST. This package is pure read-substitution
// (DecoyRigView) plus a REVERSIBLE kill-switch degradation (Trigger drives
// deadman.Lockdown + the persisted lockdown latch). There is deliberately NO
// code path that deletes, truncates, or overwrites real data — a destructive
// duress-wipe is an EXPLICIT anti-feature (security theater + self-DoS +
// detectable). nowipe_test.go statically asserts this package contains no
// destructive filesystem or credential-revocation call.
//
// The credential comparison is constant-time over fixed-width (32-byte) argon2id
// digests, with no length leak and no branch that reveals which slot matched
// (Resolve). Activation is audit-logged generically so the entry never reveals
// which credential was used (DUR-03).
package duress
