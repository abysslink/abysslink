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

// parse.go holds the pure, GOOS-independent parsers. Every parser fails
// CLOSED: only an exact-match affirmative literal yields StateOK; anything
// unrecognized is StateWarn; a positively matched weakened literal is
// StateFail. Exit codes are NEVER an input to any parser.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// firstNonEmptyLine returns the first non-blank line of s, or "".
func firstNonEmptyLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			return strings.TrimRight(ln, "\r")
		}
	}
	return ""
}

// prefixedValue extracts the value after prefix on the first non-empty line:
// trailing period tolerated, surrounding space trimmed, lower-cased for
// case-insensitive matching. ok=false when the prefix is absent.
func prefixedValue(stdout, prefix string) (value string, ok bool) {
	line := firstNonEmptyLine(stdout)
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	v := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	v = strings.TrimSuffix(v, ".")
	return strings.ToLower(v), true
}

// parseCSRUtilStatus classifies `csrutil status` stdout. Exact value match
// only: "enabled" => OK; "disabled" (ASSUMED literal) => FAIL; everything
// else — Apple Internal, unknown (Custom Configuration), residue, empty
// output — => WARN. The exit code is deliberately not an input.
func parseCSRUtilStatus(stdout string) (State, string, string) {
	v, ok := prefixedValue(stdout, csrutilSIPPrefix)
	if !ok {
		return StateWarn, "cannot determine SIP state (unrecognized csrutil output)", firstNonEmptyLine(stdout)
	}
	switch v {
	case csrutilSIPEnabled:
		return StateOK, "System Integrity Protection is enabled", firstNonEmptyLine(stdout)
	case "disabled":
		return StateFail, "System Integrity Protection is DISABLED (verified)", firstNonEmptyLine(stdout)
	default:
		return StateWarn, fmt.Sprintf("SIP state indeterminate: %q", v), firstNonEmptyLine(stdout)
	}
}

// parseAuthenticatedRoot classifies `csrutil authenticated-root status`
// stdout: "enabled" => OK; "disabled" (ASSUMED) => FAIL; else WARN.
func parseAuthenticatedRoot(stdout string) (State, string, string) {
	v, ok := prefixedValue(stdout, csrutilAuthRootPrefix)
	if !ok {
		return StateWarn, "cannot determine Authenticated Root state (unrecognized csrutil output)", firstNonEmptyLine(stdout)
	}
	switch v {
	case "enabled":
		return StateOK, "Authenticated Root (SSV) is enabled", firstNonEmptyLine(stdout)
	case "disabled":
		return StateFail, "Authenticated Root (SSV) is DISABLED (verified)", firstNonEmptyLine(stdout)
	default:
		return StateWarn, fmt.Sprintf("Authenticated Root state indeterminate: %q", v), firstNonEmptyLine(stdout)
	}
}

// iBridgeDoc is the subset of `system_profiler SPiBridgeDataType -json`
// output the probe consumes.
type iBridgeDoc struct {
	Sections []map[string]any `json:"SPiBridgeDataType"`
}

// parseIBridgeJSON classifies the boot-policy JSON. OK requires ALL THREE of
// ibridge_secure_boot == "Full Security", ibridge_sb_sip == "Enabled",
// ibridge_sb_ssv == "Enabled". A known downgrade value (Reduced/Permissive/
// Medium Security — ASSUMED) is FAIL. An absent/empty section (Intel non-T2 —
// ASSUMED), bad JSON, or an unknown value is WARN ("cannot attest on this
// platform") — never OK.
func parseIBridgeJSON(stdout string) (State, string, string) {
	var doc iBridgeDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		return StateWarn, "cannot parse system_profiler boot-policy JSON", ""
	}
	if len(doc.Sections) == 0 {
		return StateWarn, "cannot attest boot policy on this platform (no iBridge/boot-policy data)", ""
	}
	s := doc.Sections[0]
	sb, _ := s[iBridgeSecureBootKey].(string)
	sip, _ := s[iBridgeSIPKey].(string)
	ssv, _ := s[iBridgeSSVKey].(string)
	evidence := fmt.Sprintf("secure_boot=%q sip=%q ssv=%q", sb, sip, ssv)
	if sb == iBridgeFullSecurity && sip == iBridgeEnabled && ssv == iBridgeEnabled {
		return StateOK, "boot policy is Full Security with SIP and SSV enabled", evidence
	}
	if assumedIBridgeDowngrades[sb] {
		return StateFail, fmt.Sprintf("boot security policy is downgraded: %q", sb), evidence
	}
	return StateWarn, "cannot attest boot policy (unknown or incomplete iBridge values)", evidence
}

// parseEFIVarByte extracts the single data byte of an efivarfs variable read.
// Fail-closed length check: the file must be EXACTLY 5 bytes (4 LE attribute
// bytes — skipped unconditionally, never validated — plus 1 data byte).
func parseEFIVarByte(data []byte) (byte, error) {
	if len(data) != efivarLen {
		return 0, fmt.Errorf("attest: efivar length %d, want exactly %d", len(data), efivarLen)
	}
	return data[4], nil
}

// parseMokutilState scans `mokutil --sb-state` stdout for the exact known
// literals. It returns the corroboration state and whether any literal
// matched; the caller applies it DOWNGRADE-ONLY (it can never upgrade the
// efivar-derived state, and mokutil's exit code is ignored — it exits 0 on
// disabled, a confirmed lie).
func parseMokutilState(stdout string) (State, bool, string) {
	switch {
	case strings.Contains(stdout, mokutilShimDisabled):
		return StateWarn, true, mokutilShimDisabled
	case strings.Contains(stdout, mokutilSetupMode):
		return StateWarn, true, mokutilSetupMode
	case strings.Contains(stdout, mokutilDisabled):
		return StateFail, true, mokutilDisabled
	case strings.Contains(stdout, mokutilEnabled):
		return StateOK, true, mokutilEnabled
	default:
		return StateWarn, false, ""
	}
}

// pcrBankRe matches a bank header line (both man-page "sha1 :" and 5.x
// runtime "  sha256:" shapes).
var pcrBankRe = regexp.MustCompile(`^\s*([a-z0-9_]+)\s*:\s*$`)

// pcrValueRe matches one PCR value line (optional 0x prefix, either hex case).
var pcrValueRe = regexp.MustCompile(`^\s*(\d+)\s*:\s*(?:0x)?([0-9a-fA-F]+)\s*$`)

// parsePCRRead classifies tpm2_pcrread stdout: at least one bank with 8
// parsed PCR values is OK ("TPM present and readable"); anything else —
// garbage YAML, empty output, partial banks — is WARN. This probe has no FAIL
// state: a readable TPM is OK, everything else is indeterminate.
func parsePCRRead(stdout string) (State, string, string) {
	bank := ""
	counts := map[string]int{}
	for _, ln := range strings.Split(stdout, "\n") {
		if m := pcrBankRe.FindStringSubmatch(ln); m != nil {
			bank = m[1]
			continue
		}
		if bank == "" {
			continue
		}
		if pcrValueRe.MatchString(ln) {
			counts[bank]++
		}
	}
	for b, n := range counts {
		if n >= 8 {
			return StateOK, "TPM present and PCR banks readable", fmt.Sprintf("bank %s: %d PCRs", b, n)
		}
	}
	return StateWarn, "cannot read TPM PCR banks (unrecognized tpm2_pcrread output)", ""
}
