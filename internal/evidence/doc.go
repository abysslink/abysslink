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

// Package evidence builds and verifies signed audit-evidence bundles
// (`.alevidence`, a tar.gz): a tamper-evident, externally-verifiable package of
// what every agent did on a rig, suitable to hand to a SOC 2 auditor or ingest
// into a compliance platform.
//
// WHY ASYMMETRIC. The audit chain itself is HMAC-signed — tamper-evident only
// to a holder of the secret keychain key, so an external auditor cannot verify
// it. The evidence bundle therefore adds an ed25519 signature over a manifest
// that ATTESTS the chain-verification result (VALID/entry-count/epoch, produced
// by the operator's abysslink which does hold the HMAC key) plus the SHA-256 of
// every bundled file. The auditor verifies the ed25519 signature with the public
// key shipped in the bundle, and pins that key's fingerprint out-of-band (the
// operator states it once) — the same trust model as an SSH host key. This is
// an honest attestation-by-the-operator, not a zero-trust proof: the bundle
// proves "abysslink holding evidence key <fp> attests this", nothing more.
//
// Scope (v1): single-rig, local file output only. Multi-rig aggregation, org
// policy, and dashboards are the paid Teams plane and never live here — the
// bundle FORMAT (versioned) is the contract that plane consumes.
package evidence
