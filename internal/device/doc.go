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

// Package device implements Phase 28 device enrollment v2 (DEVC-01..04):
// a JSON-backed registry of enrolled phone devices, each carrying an opaque
// push token, a bearer credential (stored only as a SHA-256 hash), and a
// short-lived SSH user certificate minted by an in-process ed25519 CA whose
// private key lives exclusively in the OS keychain.
//
// Invariants:
//   - The bearer plaintext and the device SSH private key exist only inside
//     the one-time Bundle returned by Enroll/Rotate. They are never written
//     to disk, never logged, and never serialized by any Store method.
//   - Every mutation of the records file goes through internal/audit
//     (atomic temp+rename, backup, audit-log entry) at mode 0600.
//   - Revocation blanks the push token and bearer hash so no verifiable
//     credential material remains behind, and records the certificate
//     serial in a revoked_serials list for downstream RevokedKeys wiring.
//   - All randomness comes from crypto/rand.
package device
