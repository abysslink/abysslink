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

// Package hwkey creates and verifies hardware-backed SSH keys (HWK-01..04).
//
// It sits structurally beside internal/secrets: one small Provider interface,
// per-OS build-tagged NewProvider factories, a MockProvider for CLI tests, and
// sentinel errors matched with errors.Is. It is deliberately a separate
// package: secrets guards secret BYTES, while hwkey never handles secret
// material at all — sk private-key files are opaque handles whose actual
// private key lives inside the Secure Enclave or the FIDO2 authenticator.
//
// Invariants (every one has a test in the fail-closed battery):
//
//   - FAIL CLOSED. Enrollment refuses unless the produced public key is
//     verifiably sk-backed (first pub token sk-*, ssh-keygen -l shortname
//     ending -SK). On any miss the produced files are DELETED and
//     ErrSoftwareKey is returned. There is no branch that generates or accepts
//     a software key.
//   - NO SECRETS HANDLED. Authenticator PINs and passphrases are typed by the
//     operator on the inherited TTY and read by OpenSSH itself; abysslink
//     never reads, stores, or transmits them. EnrollRequest carries no secret
//     fields.
//   - INTERACTIVE-ONLY ENROLLMENT. Enroll requires a live terminal (ErrNoTTY
//     otherwise) — touch/PIN flows never run unattended and can never hang a
//     script.
//   - CGO-FREE. Everything is pure Go plus CLI shell-outs through
//     shell.Runner (sc_auth, ssh-keygen); no PCSC/libtpm/libfido2 linkage.
//     The cgo-guard workflow cross-builds this package for all four targets.
//   - VERIFY NEVER GUESSES. A parse miss on a public key is an error, never
//     Hardware=true and never "software" — doctor surfaces WARN, never OK.
package hwkey
