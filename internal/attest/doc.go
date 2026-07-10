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

// Package attest reads LOCAL boot-state posture only (ATT-01/02): macOS SIP
// and boot policy, Linux Secure Boot EFI variables and TPM PCR readability.
//
// LOCAL-ONLY INVARIANT: this package performs no network I/O and talks to no
// SaaS verifier — it must not import net, net/http, or any network-capable
// package. The invariant is enforced by TestAttestNoNetworkImports, an
// import-ALLOWLIST test: adding a networked import fails the build's test
// gate by construction.
//
// FAIL-CLOSED TRI-STATE: every probe reports StateOK only on an exact-match
// affirmative literal from a successful probe. A missing tool, a permission
// error, unrecognized output, or an unsupported platform reports StateWarn —
// never a false OK. A positively verified weakened posture (SIP disabled,
// Secure Boot byte 0) reports StateFail. The zero value of State is StateWarn
// so a forgotten assignment can never read as OK. State is never derived from
// exit codes (csrutil and mokutil exit 0 on disabled — confirmed lies).
//
// HONEST LIMITATION (documented, not an overclaim): this is local posture
// reading, not remote attestation. It does not produce signed quotes and does
// not prove runtime integrity; it exists so `abysslink status` and `doctor`
// can surface a weakened boot chain instead of staying silent.
package attest
