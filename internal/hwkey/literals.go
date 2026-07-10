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

package hwkey

// This file is the single home for every string literal the package matches or
// emits on argv, tagged CONFIRMED (observed live or in OpenSSH/Apple source)
// or ASSUMED (single-source / never observed on hardware). Parser contract: an
// ASSUMED literal that fails to match can only produce a refusal or an error —
// never a false success and never a software-key fallback.

// CONFIRMED literals.
const (
	// enclaveDylibPath is Apple's OpenSSH sk-api provider module. CONFIRMED:
	// exports _sk_api_version/_sk_enroll/_sk_sign/_sk_load_resident_keys.
	enclaveDylibPath = "/usr/lib/ssh-keychain.dylib"

	// scAuthKeyTypeP256NE is the ONLY -k value this package will ever place on
	// a sc_auth argv: P-256, non-exportable. CONFIRMED as the non-exportable
	// enclave type. The exportable "p-256" and the silently-failing "p-384-ne"
	// are unreachable by construction (single-value allowlist).
	scAuthKeyTypeP256NE = "p-256-ne"

	// scAuthProtectionBio is the ONLY -t protection value: user presence via
	// biometrics. There is no code path or config field that can emit -t none.
	scAuthProtectionBio = "bio"

	// Public-key type tokens (CONFIRMED, from OpenSSH sshkey.c). These are
	// wire-format TYPE names, not credentials — gosec G101 false-positives on
	// the "key" naming.
	tokenSKEd25519   = "sk-ssh-ed25519@openssh.com"                  //nolint:gosec // G101: public key TYPE token, not a credential
	tokenSKECDSA     = "sk-ecdsa-sha2-nistp256@openssh.com"          //nolint:gosec // G101: public key TYPE token, not a credential
	tokenWebauthnSK  = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" //nolint:gosec // G101: public key TYPE token, not a credential
	tokenSKEd25519Ct = "sk-ssh-ed25519-cert-v01@openssh.com"         //nolint:gosec // G101: public key TYPE token, not a credential
	tokenSKECDSACt   = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" //nolint:gosec // G101: public key TYPE token, not a credential
	certSuffix       = "-cert-v01@openssh.com"

	// enclaveHandlePrefix is the resident-key handle filename prefix
	// `ssh-keygen -K` produces for enclave keys (source format string
	// "id_%s_rk%s%s" with ecdsa_sk; CONFIRMED in ssh-keygen.c, never observed
	// on hardware — the zero-files fail-closed check does not depend on it
	// being the ONLY possible name, it requires at least one match).
	enclaveHandlePrefix = "id_ecdsa_sk_rk"

	// Key type allowlist values for FIDO2 (CONFIRMED ssh-keygen -t values).
	keyTypeEd25519SK = "ed25519-sk"
	keyTypeECDSASK   = "ecdsa-sk"

	// Version floor (HWK-02): OpenSSH >= 10.0.
	FloorMajor = 10
	FloorMinor = 0
)

// ASSUMED literals — tagged per §12 of the phase design. None of these is
// load-bearing for a success decision; each can only refuse or degrade:
//
//   - ASSUMED: sc_auth create-ctk-identity success shape is silent + exit 0
//     (not smoked on hardware). We therefore NEVER trust the create exit code
//     alone: enrollment post-verifies via list-ctk-identities row count.
//   - ASSUMED: sc_auth list-ctk-identities -t ssh row format when identities
//     exist (only the empty header + exit 0 case is REAL-CONFIRMED). The
//     parser is defensive: >= 1 non-header row containing the label, else
//     ErrEnrollFailed.
//   - ASSUMED: `ssh-keygen -K` prompts "Enter PIN for authenticator: " even
//     for bio-protected enclave keys and accepts an empty PIN (single-source
//     gist). The prompt is handled by OpenSSH on the inherited TTY; abysslink
//     never matches or answers it.
//   - ASSUMED: "Saved ECDSA-SK key to id_ecdsa_sk_rk" / "Saved ED25519-SK key
//     ssh:foo to id_ed25519_sk_rk_foo" output lines (source format confirmed,
//     never observed). Not matched — success is decided by counting produced
//     files, never by parsing saved-key lines.
//   - ASSUMED: attempting enclave key GENERATION via `ssh-keygen -t ecdsa-sk
//     -w ssh-keychain.dylib` fails (Apple module lacks sk_enroll generation).
//     The exact failure literal is unknown; the flow never attempts it.
//   - ASSUMED: Homebrew ssh ignores the SSH_SK_PROVIDER env var (single-source
//     mindrot post) — connection guidance therefore always uses the explicit
//     -o SecurityKeyProvider flag, never the env var.
//   - ASSUMED: the macOS floor for the dylib sk-api is macOS 15 Sequoia. Never
//     version-matched: the runtime "provider ... is not an OpenSSH FIDO
//     library" stderr at enroll time is the too-old signal, and it maps to
//     ErrEnrollFailed / ErrNotAvailable, never to a fallback.
//   - ASSUMED: the composed line "Key enrollment failed: device not found"
//     (halves source-confirmed, composition never observed) and the retry
//     variant "You may need to touch your authenticator again to authorize
//     key generation." — neither is string-matched: ANY RunInteractive
//     failure maps to ErrEnrollFailed regardless of wording.
//   - ASSUMED: ssh-keygen -l cert shortname tokens, e.g. "(ED25519-SK-CERT)".
//     Classified hardware on the -SK-CERT suffix; an unknown token is an
//     error, never Hardware=true.
//   - ASSUMED: the upstream literal "internal security key support not
//     enabled" (which Linux builds emit it is unverified). Not matched — the
//     resulting non-zero exit is ErrEnrollFailed like any other failure.
//   - ASSUMED: Linux vendor `ssh -V` shape "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5,
//     OpenSSL ..." (vendor suffix before the comma). The version regexp is
//     anchored at offset 0 and ignores everything after the pN suffix, so
//     vendor suffixes cannot break the parse; a shape drift fails closed to
//     ErrParse.
//   - ASSUMED: passphrase-prompt wording on OpenSSH 8.2-9.x (quoted-path form
//     confirmed only on 10.x/master). Irrelevant below the 10.0 floor — those
//     versions are refused pre-exec.
