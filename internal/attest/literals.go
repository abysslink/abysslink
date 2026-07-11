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

package attest

// This file is the single home for every string/byte literal the probes
// match, tagged CONFIRMED (observed live / in tool source) or ASSUMED
// (assembled from binary strings / man pages, never observed). Parser
// contract: an ASSUMED literal that fails to match can only produce WARN —
// never OK, and a matched ASSUMED literal can only produce FAIL or WARN
// (verified-bad or downgrade), never upgrade a state.

// CONFIRMED literals.
const (
	// csrutilSIPPrefix anchors the `csrutil status` first line. CONFIRMED live.
	csrutilSIPPrefix = "System Integrity Protection status: "
	// csrutilSIPEnabled — CONFIRMED live ("enabled." with trailing period;
	// the period is tolerated and the value token matched case-insensitively).
	csrutilSIPEnabled = "enabled"

	// csrutilAuthRootPrefix anchors `csrutil authenticated-root status`.
	// CONFIRMED live; value "enabled" has NO trailing period on current macOS.
	csrutilAuthRootPrefix = "Authenticated Root status: "

	// iBridge JSON keys + the Full Security affirmative values. The section
	// key and full-security values are CONFIRMED from system_profiler -json.
	iBridgeSectionKey    = "SPiBridgeDataType"
	iBridgeSecureBootKey = "ibridge_secure_boot"
	iBridgeSIPKey        = "ibridge_sb_sip"
	iBridgeSSVKey        = "ibridge_sb_ssv"
	iBridgeFullSecurity  = "Full Security"
	iBridgeEnabled       = "Enabled"

	// efivarSecureBootName / efivarSetupModeName are the EFI global-scope
	// variables (GUID CONFIRMED, UEFI spec).
	efivarGUID           = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	efivarSecureBootName = "SecureBoot-" + efivarGUID
	efivarSetupModeName  = "SetupMode-" + efivarGUID
	// efivarLen: 4 little-endian attribute bytes + exactly 1 data byte. The
	// attribute u32 (ASSUMED 0x00000006) is skipped unconditionally and never
	// validated; only the total length==5 is enforced (fail closed on drift).
	efivarLen = 5

	// defaultEFIVarsDir is the efivarfs mount point (CONFIRMED).
	defaultEFIVarsDir = "/sys/firmware/efi/efivars"

	// mokutil --sb-state literals. "SecureBoot enabled" / "SecureBoot
	// disabled" are CONFIRMED from mokutil source; note mokutil exits 0 even
	// when disabled (exit-code lie — state comes from stdout literals only).
	mokutilEnabled      = "SecureBoot enabled"
	mokutilDisabled     = "SecureBoot disabled"
	mokutilSetupMode    = "Platform is in Setup Mode"
	mokutilShimDisabled = "SecureBoot validation is disabled in shim"

	// tpmPCRSelection pins both the bank selection and the TCTI. The -T flag
	// makes an inherited TPM2TOOLS_TCTI (simulator redirect) inert.
	tpmPCRSelection = "sha256:0,1,2,3,4,5,6,7"
	tpmTCTI         = "device:/dev/tpmrm0"
)

// ASSUMED literals — tagged per §12 of the phase design:
//
//   - ASSUMED: "System Integrity Protection status: disabled." (from csrutil
//     binary strings, never observed live). Matching it can only FAIL.
//   - ASSUMED: csrutil exits 0 when SIP is disabled — exit codes are never
//     consulted, so the assumption is inert.
//   - ASSUMED: "Authenticated Root status: disabled" (assembled from the
//     binary format string). Matching it can only FAIL.
//   - ASSUMED: the one-line "unknown (Custom Configuration)." rendering and
//     its concatenated warning lines — anything that is not an exact
//     enabled/disabled value is WARN, so drift is safe.
//   - ASSUMED: ibridge_secure_boot values other than "Full Security"
//     ("Reduced Security" / "Permissive Security" / "Medium Security").
//     Matching one can only FAIL; an unknown value is WARN.
//   - ASSUMED: SPiBridgeDataType is empty + exit 0 on Intel non-T2 Macs —
//     the absent-section taxonomy is WARN ("cannot attest on this platform").
//   - ASSUMED: the SecureBoot efivar attribute u32 == 0x00000006 — skipped
//     unconditionally, never validated; only file-length==5 is enforced.
//   - ASSUMED: mokutil error messages go to stderr and "EFI variables are not
//     supported on this system" exits 1 — irrelevant: mokutil is
//     corroboration-only and can only downgrade.
//   - ASSUMED: the legacy mokutil string "This system doesn't support Secure
//     Boot" (version drift) — unmatched output has no effect (efivar primary).
//   - ASSUMED: tpm2_pcrread 5.x runtime YAML shape (two-space indent, "0x"
//     hex) vs the man-page "sha1 :" shape — the parser accepts BOTH; garbage
//     is WARN.
//   - ASSUMED: TCTI failure stderr text — never string-matched; any non-zero
//     exit or empty stdout is WARN.
//   - NOT SHIPPED (documented): tpm2_quote stdout shape, bputil -d root-mode
//     output (root-only even for display), T2 `nvram` tab-separated stdout.
var assumedIBridgeDowngrades = map[string]bool{
	"Reduced Security":    true,
	"Permissive Security": true,
	"Medium Security":     true,
}
