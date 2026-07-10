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

// monotonic_test.go — the MONOTONICITY property battery: corrupting,
// truncating, or deleting any probe input can NEVER upgrade the state. The
// precise invariant tested: a corrupted variant may report StateOK only if
// the pristine input already reported StateOK (WARN→OK and FAIL→OK are
// forbidden by construction; degradation is always allowed).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireNoUpgrade asserts the monotonicity invariant for one parser over
// every prefix-truncation of input (including the empty string) and a set of
// byte corruptions.
func requireNoUpgrade(t *testing.T, name, input string, parse func(string) State) {
	t.Helper()
	base := parse(input)
	for i := 0; i <= len(input); i++ {
		got := parse(input[:i])
		if got == StateOK {
			assert.Equal(t, StateOK, base,
				"%s: truncation at %d upgraded %v -> OK (forbidden)", name, i, base)
		}
	}
	// Byte corruptions: flip each byte to 'X'.
	for i := 0; i < len(input); i++ {
		mutated := []byte(input)
		mutated[i] = 'X'
		got := parse(string(mutated))
		if got == StateOK {
			assert.Equal(t, StateOK, base,
				"%s: corruption at %d upgraded %v -> OK (forbidden)", name, i, base)
		}
	}
}

func TestAttestMonotonicity(t *testing.T) {
	t.Run("csrutil_sip", func(t *testing.T) {
		parse := func(s string) State { st, _, _ := parseCSRUtilStatus(s); return st }
		requireNoUpgrade(t, "sip_disabled", "System Integrity Protection status: disabled.\n", parse)
		requireNoUpgrade(t, "sip_custom", "System Integrity Protection status: unknown (Custom Configuration).\n", parse)
		requireNoUpgrade(t, "sip_garbage", "csrutil: not found\n", parse)
	})

	t.Run("authenticated_root", func(t *testing.T) {
		parse := func(s string) State { st, _, _ := parseAuthenticatedRoot(s); return st }
		requireNoUpgrade(t, "ar_disabled", "Authenticated Root status: disabled\n", parse)
	})

	t.Run("ibridge_json", func(t *testing.T) {
		parse := func(s string) State { st, _, _ := parseIBridgeJSON(s); return st }
		requireNoUpgrade(t, "ibridge_reduced",
			`{"SPiBridgeDataType":[{"ibridge_secure_boot":"Reduced Security","ibridge_sb_sip":"Enabled","ibridge_sb_ssv":"Enabled"}]}`, parse)
		requireNoUpgrade(t, "ibridge_empty", `{"SPiBridgeDataType":[]}`, parse)
	})

	t.Run("mokutil", func(t *testing.T) {
		// mokutil is corroboration-only: its parse may claim OK ("SecureBoot
		// enabled") but downgradeOnly guarantees that can never LIFT the
		// primary state — pinned separately in
		// TestMokutil_CorroborationOnlyDowngrades. Here: corrupting a
		// disabled/shim signal can only lose the signal (no effect), never
		// mint an enabled signal.
		input := "SecureBoot disabled\n"
		for i := 0; i <= len(input); i++ {
			st, matched, _ := parseMokutilState(input[:i])
			if matched {
				assert.NotEqual(t, StateOK, st, "corrupting a disabled signal must not become an enabled signal")
			}
		}
	})

	t.Run("pcrread", func(t *testing.T) {
		parse := func(s string) State { st, _, _ := parsePCRRead(s); return st }
		requireNoUpgrade(t, "pcr_garbage", "ERROR: TCTI\n", parse)
		// Truncating a GOOD PCR listing may stay OK only while >= 8 PCRs of
		// one bank survive; asserted via base==OK (allowed by the invariant).
		requireNoUpgrade(t, "pcr_good", pcrRuntimeShape, parse)
	})

	t.Run("efivars_files", func(t *testing.T) {
		ctx := context.Background()
		// Baseline: the ONLY affirmative fixture.
		good := efiFixture(t, efiVar(1), efiVar(0))
		require.Equal(t, StateOK, good.probeSecureBootLinux(ctx).State)

		type variant struct {
			name       string
			secureBoot []byte // nil = absent
			setupMode  []byte
		}
		variants := []variant{
			{"secureboot_deleted", nil, efiVar(0)},
			{"secureboot_truncated", []byte{6, 0}, efiVar(0)},
			{"secureboot_zero", efiVar(0), efiVar(0)},
			{"secureboot_junk_value", efiVar(9), efiVar(0)},
			{"secureboot_extended", append(efiVar(1), 1), efiVar(0)},
			{"setupmode_deleted", efiVar(1), nil},
			{"setupmode_one", efiVar(1), efiVar(1)},
			{"setupmode_truncated", efiVar(1), []byte{6}},
			{"both_deleted", nil, nil},
		}
		for _, v := range variants {
			t.Run(v.name, func(t *testing.T) {
				p := efiFixture(t, v.secureBoot, v.setupMode)
				st := p.probeSecureBootLinux(ctx).State
				assert.NotEqual(t, StateOK, st,
					"corrupted efivar input %q must never report OK", v.name)
			})
		}

		t.Run("efi_dir_deleted", func(t *testing.T) {
			p := efiFixture(t, efiVar(1), efiVar(0))
			require.NoError(t, os.RemoveAll(filepath.Dir(p.EFIVarsDir)))
			st := p.probeSecureBootLinux(ctx).State
			assert.Equal(t, StateWarn, st, "deleting the EFI tree degrades to WARN, never OK")
		})
	})
}

// TestMonotonicityHelperSelfCheck guards the battery itself: the helper must
// accept an OK baseline staying OK under a no-op "corruption".
func TestMonotonicityHelperSelfCheck(t *testing.T) {
	parse := func(s string) State { st, _, _ := parseCSRUtilStatus(s); return st }
	base := parse("System Integrity Protection status: enabled.\n")
	require.Equal(t, StateOK, base)
	requireNoUpgrade(t, "sip_enabled", "System Integrity Protection status: enabled.\n", parse)
	_ = fmt.Sprintf("%v", base)
}
