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

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateZeroValueIsWarn(t *testing.T) {
	var s State
	assert.Equal(t, StateWarn, s, "a forgotten assignment can never read as OK")
	assert.Equal(t, "warn", s.String())
	assert.Equal(t, "ok", StateOK.String())
	assert.Equal(t, "fail", StateFail.String())

	var r Result
	assert.Equal(t, StateWarn, r.State, "zero-value Result fails closed to WARN")
}

func TestSummarize(t *testing.T) {
	assert.Equal(t, "unverified", Summarize(nil), "zero probes can never be verified")
	assert.Equal(t, "verified", Summarize([]Result{{State: StateOK}, {State: StateOK}}))
	assert.Equal(t, "unverified", Summarize([]Result{{State: StateOK}, {State: StateWarn}}))
	assert.Equal(t, "weakened", Summarize([]Result{{State: StateOK}, {State: StateFail}}))
	assert.Equal(t, "weakened", Summarize([]Result{{State: StateWarn}, {State: StateFail}}))
	assert.Equal(t, "unverified", Summarize([]Result{{State: StateWarn}}))
}

func TestParseCSRUtil_Literals(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   State
	}{
		{"enabled", "System Integrity Protection status: enabled.\n", StateOK},
		{"disabled_assumed", "System Integrity Protection status: disabled.\n", StateFail},
		{"apple_internal", "System Integrity Protection status: enabled (Apple Internal).\n", StateWarn},
		{"custom_config", "System Integrity Protection status: unknown (Custom Configuration).\n", StateWarn},
		{"residue", "csrutil: unknown command\n", StateWarn},
		{"empty", "", StateWarn},
		{"case_insensitive_value", "System Integrity Protection status: Enabled.\n", StateOK},
		{"no_trailing_period", "System Integrity Protection status: enabled\n", StateOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, detail, _ := parseCSRUtilStatus(tc.stdout)
			assert.Equal(t, tc.want, state, "detail: %s", detail)
		})
	}
}

// TestProbeSIP_ExitCodeIgnored: state comes from stdout literals ONLY —
// csrutil exits 0 on disabled (the lie), and a nonzero exit with no literal
// is WARN, never OK.
func TestProbeSIP_ExitCodeIgnored(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled_with_exit_0_is_fail", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{
			Stdout: "System Integrity Protection status: disabled.\n", ExitCode: 0,
		}})
		p := New(r)
		res := p.probeSIP(ctx)
		assert.Equal(t, StateFail, res.State)
	})
	t.Run("nonzero_no_literal_is_warn", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stderr: "boom", ExitCode: 1}})
		p := New(r)
		res := p.probeSIP(ctx)
		assert.Equal(t, StateWarn, res.State)
	})
	t.Run("tool_missing_is_warn", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Err: assert.AnError})
		p := New(r)
		res := p.probeSIP(ctx)
		assert.Equal(t, StateWarn, res.State, "evidence suppression (deleted tool) never yields green")
	})
	t.Run("locale_pinned", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{
			Stdout: "System Integrity Protection status: enabled.\n", ExitCode: 0,
		}})
		p := New(r)
		_ = p.probeSIP(ctx)
		calls := r.RecordedCalls()
		require.Len(t, calls, 1)
		assert.Equal(t, "C", calls[0].Env["LC_ALL"])
		assert.Equal(t, "C", calls[0].Env["LANG"])
	})
}

func TestParseAuthenticatedRoot(t *testing.T) {
	st, _, _ := parseAuthenticatedRoot("Authenticated Root status: enabled\n")
	assert.Equal(t, StateOK, st)
	st, _, _ = parseAuthenticatedRoot("Authenticated Root status: disabled\n")
	assert.Equal(t, StateFail, st)
	st, _, _ = parseAuthenticatedRoot("garbage\n")
	assert.Equal(t, StateWarn, st)
}

func TestParseIBridgeJSON(t *testing.T) {
	full := `{"SPiBridgeDataType":[{"ibridge_secure_boot":"Full Security","ibridge_sb_sip":"Enabled","ibridge_sb_ssv":"Enabled"}]}`
	st, _, _ := parseIBridgeJSON(full)
	assert.Equal(t, StateOK, st, "all three exact values required for OK")

	reduced := `{"SPiBridgeDataType":[{"ibridge_secure_boot":"Reduced Security","ibridge_sb_sip":"Enabled","ibridge_sb_ssv":"Enabled"}]}`
	st, _, _ = parseIBridgeJSON(reduced)
	assert.Equal(t, StateFail, st)

	permissive := `{"SPiBridgeDataType":[{"ibridge_secure_boot":"Permissive Security"}]}`
	st, _, _ = parseIBridgeJSON(permissive)
	assert.Equal(t, StateFail, st)

	// One of the three missing → WARN, never OK.
	partial := `{"SPiBridgeDataType":[{"ibridge_secure_boot":"Full Security","ibridge_sb_sip":"Enabled"}]}`
	st, _, _ = parseIBridgeJSON(partial)
	assert.Equal(t, StateWarn, st)

	empty := `{"SPiBridgeDataType":[]}`
	st, detail, _ := parseIBridgeJSON(empty)
	assert.Equal(t, StateWarn, st)
	assert.Contains(t, detail, "cannot attest")

	st, _, _ = parseIBridgeJSON("not json at all")
	assert.Equal(t, StateWarn, st)

	unknown := `{"SPiBridgeDataType":[{"ibridge_secure_boot":"Quantum Security","ibridge_sb_sip":"Enabled","ibridge_sb_ssv":"Enabled"}]}`
	st, _, _ = parseIBridgeJSON(unknown)
	assert.Equal(t, StateWarn, st, "unknown literal drift can only degrade")
}

// efiFixture builds an efivars dir under a real "efi" parent and writes the
// SecureBoot/SetupMode variables (attrBytes + 1 data byte each; nil skips).
func efiFixture(t *testing.T, secureBoot, setupMode []byte) *Prober {
	t.Helper()
	efiDir := filepath.Join(t.TempDir(), "efi")
	varsDir := filepath.Join(efiDir, "efivars")
	require.NoError(t, os.MkdirAll(varsDir, 0o755))
	if secureBoot != nil {
		require.NoError(t, os.WriteFile(filepath.Join(varsDir, efivarSecureBootName), secureBoot, 0o644))
	}
	if setupMode != nil {
		require.NoError(t, os.WriteFile(filepath.Join(varsDir, efivarSetupModeName), setupMode, 0o644))
	}
	p := New(shell.NewMockRunner())
	p.EFIVarsDir = varsDir
	p.LookPath = func(string) bool { return false } // no mokutil unless a test opts in
	return p
}

func efiVar(b byte) []byte { return []byte{6, 0, 0, 0, b} }

func TestParseEFIVar_FailClosed(t *testing.T) {
	t.Run("enabled_and_enforcing_is_ok", func(t *testing.T) {
		p := efiFixture(t, efiVar(1), efiVar(0))
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateOK, res.State, "the ONLY affirmative path: SecureBoot=1 AND SetupMode=0")
	})
	t.Run("byte_zero_is_fail", func(t *testing.T) {
		p := efiFixture(t, efiVar(0), efiVar(0))
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateFail, res.State)
	})
	t.Run("byte_seven_is_warn", func(t *testing.T) {
		p := efiFixture(t, efiVar(7), efiVar(0))
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State, "vendor-junk value never OK, never guessed as FAIL")
	})
	t.Run("short_file_is_warn", func(t *testing.T) {
		p := efiFixture(t, []byte{1}, efiVar(0))
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State, "len != 5 fails closed")
	})
	t.Run("long_file_is_warn", func(t *testing.T) {
		p := efiFixture(t, append(efiVar(1), 0xFF), efiVar(0))
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State)
	})
	t.Run("setup_mode_overrides_enabled", func(t *testing.T) {
		p := efiFixture(t, efiVar(1), efiVar(1))
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State, "SetupMode=1 beats SecureBoot=1 — never OK")
	})
	t.Run("setup_mode_missing_is_warn", func(t *testing.T) {
		p := efiFixture(t, efiVar(1), nil)
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State, "deleting SetupMode must not upgrade to OK (monotone)")
	})
	t.Run("secureboot_var_absent_is_warn", func(t *testing.T) {
		p := efiFixture(t, nil, nil)
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State)
		assert.Contains(t, res.Detail, "SecureBoot")
	})
	t.Run("no_efi_dir_is_warn_not_efi", func(t *testing.T) {
		p := New(shell.NewMockRunner())
		p.EFIVarsDir = filepath.Join(t.TempDir(), "efi", "efivars") // parent absent
		p.LookPath = func(string) bool { return false }
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State)
		assert.Contains(t, res.Detail, "not an EFI system")
	})
	t.Run("permission_denied_is_warn", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root can read a 000 file; EACCES taxonomy untestable as root")
		}
		p := efiFixture(t, efiVar(1), efiVar(0))
		require.NoError(t, os.Chmod(filepath.Join(p.EFIVarsDir, efivarSecureBootName), 0o000))
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State)
		assert.Contains(t, res.Detail, "permission")
	})
}

func TestParseMokutil(t *testing.T) {
	st, matched, _ := parseMokutilState("SecureBoot enabled\n")
	assert.True(t, matched)
	assert.Equal(t, StateOK, st)

	st, matched, _ = parseMokutilState("SecureBoot disabled\n")
	assert.True(t, matched)
	assert.Equal(t, StateFail, st)

	st, matched, _ = parseMokutilState("Platform is in Setup Mode\n")
	assert.True(t, matched)
	assert.Equal(t, StateWarn, st)

	st, matched, _ = parseMokutilState("SecureBoot enabled\nSecureBoot validation is disabled in shim\n")
	assert.True(t, matched)
	assert.Equal(t, StateWarn, st, "shim-validation-disabled wins over the enabled line")

	_, matched, _ = parseMokutilState("EFI variables are not supported on this system\n")
	assert.False(t, matched, "unknown output has no corroboration effect")
}

// TestMokutil_CorroborationOnlyDowngrades: the mokutil result can never
// upgrade the efivar-derived state; it can cap OK at WARN or force FAIL.
func TestMokutil_CorroborationOnlyDowngrades(t *testing.T) {
	t.Run("downgradeOnly_lattice", func(t *testing.T) {
		assert.Equal(t, StateOK, downgradeOnly(StateOK, StateOK))
		assert.Equal(t, StateWarn, downgradeOnly(StateOK, StateWarn))
		assert.Equal(t, StateFail, downgradeOnly(StateOK, StateFail))
		assert.Equal(t, StateWarn, downgradeOnly(StateWarn, StateOK), "corroboration NEVER upgrades")
		assert.Equal(t, StateWarn, downgradeOnly(StateWarn, StateWarn))
		assert.Equal(t, StateFail, downgradeOnly(StateWarn, StateFail))
		assert.Equal(t, StateFail, downgradeOnly(StateFail, StateOK), "a FAIL is never softened")
		assert.Equal(t, StateFail, downgradeOnly(StateFail, StateWarn))
	})

	t.Run("shim_disabled_caps_efivar_ok_at_warn", func(t *testing.T) {
		p := efiFixture(t, efiVar(1), efiVar(0))
		p.LookPath = func(name string) bool { return name == "mokutil" }
		p.Runner = shell.NewMockRunner(shell.Call{Result: shell.Result{
			Stdout: "SecureBoot validation is disabled in shim\n", ExitCode: 0,
		}})
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State, "WARN despite efivar byte 1")
	})

	t.Run("mokutil_disabled_exit0_lie_forces_fail", func(t *testing.T) {
		p := efiFixture(t, efiVar(1), efiVar(0))
		p.LookPath = func(name string) bool { return name == "mokutil" }
		p.Runner = shell.NewMockRunner(shell.Call{Result: shell.Result{
			Stdout: "SecureBoot disabled\n", ExitCode: 0, // exit 0 on disabled: the lie
		}})
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateFail, res.State, "state from stdout literals, exit code ignored")
	})

	t.Run("mokutil_enabled_never_upgrades_a_warn", func(t *testing.T) {
		p := efiFixture(t, efiVar(7), efiVar(0)) // efivar WARN
		p.LookPath = func(name string) bool { return name == "mokutil" }
		p.Runner = shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "SecureBoot enabled\n", ExitCode: 0}})
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateWarn, res.State)
	})

	t.Run("mokutil_missing_no_effect", func(t *testing.T) {
		p := efiFixture(t, efiVar(1), efiVar(0)) // LookPath false by default
		res := p.probeSecureBootLinux(context.Background())
		assert.Equal(t, StateOK, res.State)
	})
}

const pcrManPageShape = `sha1 :
  0  : 0000000000000000000000000000000000000000
  1  : 0000000000000000000000000000000000000000
  2  : 0000000000000000000000000000000000000000
  3  : 0000000000000000000000000000000000000000
  4  : 0000000000000000000000000000000000000000
  5  : 0000000000000000000000000000000000000000
  6  : 0000000000000000000000000000000000000000
  7  : 0000000000000000000000000000000000000000
`

const pcrRuntimeShape = `  sha256:
    0 : 0x44AF2D8408BE33B5B4E4A9BAAA6F21C7CFFA282DDDE2C9F9A7BBEA3F13F44C31
    1 : 0xB1676439CAC1531683990FEFE2218A43239D6FE8D9C1CD97AD24C41AAE886A5F
    2 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    3 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    4 : 0xF9DE741A8AC1A94A220C9B60E0DDDFCA8D51C75E14A9FCF9A7234A13F198E796
    5 : 0xA57BF11A98BE8D3D9E4E5EAF12EC01D1C8CDC7B5E14A9FCF9A7234A13F198E79
    6 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    7 : 0x518BD167271FBB64589C61E43D8C0165861431D8AABC58D7D16DDA9B69336AE2
`

func TestParsePCRRead_BothShapes(t *testing.T) {
	st, _, _ := parsePCRRead(pcrManPageShape)
	assert.Equal(t, StateOK, st, "man-page shape must parse")

	st, _, _ = parsePCRRead(pcrRuntimeShape)
	assert.Equal(t, StateOK, st, "5.x runtime shape (indent, 0x, uppercase) must parse")

	st, _, _ = parsePCRRead("ERROR: could not connect to TCTI\n")
	assert.Equal(t, StateWarn, st, "garbage is WARN, never OK")

	st, _, _ = parsePCRRead("")
	assert.Equal(t, StateWarn, st)

	// Fewer than 8 PCR values in every bank → WARN.
	st, _, _ = parsePCRRead("sha256:\n  0 : 0xAB\n  1 : 0xCD\n")
	assert.Equal(t, StateWarn, st)
}

func TestProbeTPM_FailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("readable_is_ok", func(t *testing.T) {
		p := New(shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: pcrRuntimeShape, ExitCode: 0}}))
		res := p.probeTPM(ctx)
		assert.Equal(t, StateOK, res.State)
	})
	t.Run("tool_missing_is_warn", func(t *testing.T) {
		p := New(shell.NewMockRunner(shell.Call{Err: assert.AnError}))
		res := p.probeTPM(ctx)
		assert.Equal(t, StateWarn, res.State)
	})
	t.Run("exit4_no_device_is_warn", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 4}})
		p := New(r)
		res := p.probeTPM(ctx)
		assert.Equal(t, StateWarn, res.State)
		assert.Contains(t, res.Detail, "tss")
		// TCTI pinned by flag so an inherited TPM2TOOLS_TCTI is inert.
		calls := r.RecordedCalls()
		require.Len(t, calls, 1)
		assert.Equal(t, []string{tpmPCRSelection, "-T", tpmTCTI}, calls[0].Args)
	})
	t.Run("garbage_yaml_is_warn", func(t *testing.T) {
		p := New(shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "%%%", ExitCode: 0}}))
		res := p.probeTPM(ctx)
		assert.Equal(t, StateWarn, res.State)
	})
}
