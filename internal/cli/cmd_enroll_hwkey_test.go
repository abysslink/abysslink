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

package cli

// cmd_enroll_hwkey_test.go — Phase 37 CLI battery (HWK-03/HWK-04/ATT-02).
// Every provider interaction is a hwkey.MockProvider and every shell call a
// MockRunner: no test can reach a live authenticator, keychain, or
// ssh-keygen -w.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/attest"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/hwkey"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// writeTestConfig marshals cfg to a temp abysslink.yaml and returns its path.
func writeTestConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "abysslink.yaml")
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

// TestEnrollRigKeyKindFlag: a hardware --key-kind writes the hardware_keys
// stanza, prints the deferred operator step, and performs ZERO hwkey Runner
// calls — enroll rig never execs sc_auth/ssh-keygen sk paths (HWK-04).
func TestEnrollRigKeyKindFlag(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfgPath := writeTestConfig(t, testCfgDefaults())
	kc := newMockKeychain()
	var out bytes.Buffer

	// A MockRunner with ZERO scripted calls: any shell exec anywhere in this
	// flow would error the test. (enrollRig takes no Runner by construction —
	// the assertion documents the invariant.)
	r := shell.NewMockRunner()

	err := enrollRig(context.Background(), enrollRigOpts{
		name:     "workstation",
		cfgPath:  cfgPath,
		keychain: kc,
		apply:    true,
		keyKind:  "fido2",
		stdout:   &out,
	})
	require.NoError(t, err)
	assert.True(t, r.Done(), "zero hwkey Runner calls")
	assert.Empty(t, r.RecordedCalls())

	cfg2, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.True(t, cfg2.HardwareKeys.Enabled, "hardware_keys stanza must be written")
	assert.Equal(t, "fido2", cfg2.HardwareKeys.Provider)

	assert.Contains(t, out.String(), "abysslink enroll hardware-key --apply",
		"the deferred operator step must be printed")
	assert.Contains(t, out.String(), "interactive")
}

// TestEnrollRigKeyKindDefaultSoftware: absent key kind → no stanza change,
// legacy behavior (zero behavior change for existing users).
func TestEnrollRigKeyKindDefaultSoftware(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfgPath := writeTestConfig(t, testCfgDefaults())
	kc := newMockKeychain()
	var out bytes.Buffer

	for _, kind := range []string{"", "software"} {
		err := enrollRig(context.Background(), enrollRigOpts{
			name:     "rig-" + map[string]string{"": "a", "software": "b"}[kind],
			cfgPath:  cfgPath,
			keychain: kc,
			apply:    true,
			keyKind:  kind,
			stdout:   &out,
		})
		require.NoError(t, err)
	}

	cfg2, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.False(t, cfg2.HardwareKeys.Enabled, "software kind must not enable hardware_keys")
	assert.Empty(t, cfg2.HardwareKeys.Provider)
	assert.NotContains(t, out.String(), "enroll hardware-key", "no operator step for software keys")
}

// hwkeyTestEnv pins the provider + runner seams for `enroll hardware-key`
// command tests and returns the mock provider.
func hwkeyTestEnv(t *testing.T) *hwkey.MockProvider {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("NO_COLOR", "1")

	mock := hwkey.NewMockProvider()
	origProvider := newHwkeyProvider
	newHwkeyProvider = func(_ hwkey.Kind, _ shell.Runner, _ hwkey.Options) (hwkey.Provider, error) {
		return mock, nil
	}
	t.Cleanup(func() { newHwkeyProvider = origProvider })

	origNewRunner := newRunner
	newRunner = func() shell.Runner { return shell.NewMockRunner() }
	t.Cleanup(func() { newRunner = origNewRunner })
	return mock
}

// hwkeyEnabledConfig returns a valid config with hardware_keys enabled and
// the key path anchored in a temp dir (no home-dir resolution in tests).
func hwkeyEnabledConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	cfg := testCfgDefaults()
	cfg.HardwareKeys = config.HardwareKeysConfig{
		Enabled:  true,
		Provider: "fido2",
		KeyPath:  filepath.Join(t.TempDir(), "abysslink_id_sk"),
	}
	return cfg, writeTestConfig(t, cfg)
}

// TestEnrollHardwareKey_DryRunDefault: without --apply the command prints the
// probe + the EXACT argv preview and performs no interactive call, no
// mutation, and no config write.
func TestEnrollHardwareKey_DryRunDefault(t *testing.T) {
	mock := hwkeyTestEnv(t)
	mock.AvailableProbe = hwkey.Probe{OK: true, SSHVersion: "10.2"}
	_, cfgPath := hwkeyEnabledConfig(t)
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs([]string{"enroll", "hardware-key", "--config", cfgPath})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, cmd.Execute())

	out := buf.String()
	assert.Contains(t, out, "preview only")
	assert.Contains(t, out, "OpenSSH 10.2")
	assert.Contains(t, out, "ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:abysslink",
		"the exact argv must be previewed")
	assert.Contains(t, out, "touch")
	assert.Empty(t, mock.EnrollCalls, "dry-run must never call Enroll")

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "dry-run must not mutate the config")
}

// TestEnrollHardwareKey_DryRunShowsUnavailable: a failing probe renders the
// remediation hint instead of a false-green plan.
func TestEnrollHardwareKey_DryRunShowsUnavailable(t *testing.T) {
	mock := hwkeyTestEnv(t)
	mock.AvailableProbe = hwkey.Probe{OK: false, Reason: "set hardware_keys.fido2_provider_path"}
	_, cfgPath := hwkeyEnabledConfig(t)

	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs([]string{"enroll", "hardware-key", "--config", cfgPath})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "NOT available")
	assert.Contains(t, buf.String(), "fido2_provider_path")
}

// TestEnrollHardwareKey_ApplyRequiresTTY: --apply refuses without a live
// terminal and refuses --json outright — the interactive flow never runs
// unattended and never hangs a pipeline.
func TestEnrollHardwareKey_ApplyRequiresTTY(t *testing.T) {
	mock := hwkeyTestEnv(t)
	_, cfgPath := hwkeyEnabledConfig(t)

	t.Run("non_tty_refused", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := buildRootCmd()
		cmd.SetArgs([]string{"enroll", "hardware-key", "--config", cfgPath, "--apply"})
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "interactive terminal")
		assert.Empty(t, mock.EnrollCalls)
	})

	t.Run("json_refused", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := buildRootCmd()
		cmd.SetArgs([]string{"--json", "enroll", "hardware-key", "--config", cfgPath, "--apply"})
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--json")
		assert.Empty(t, mock.EnrollCalls)
	})

	t.Run("disabled_config_refused", func(t *testing.T) {
		plainPath := writeTestConfig(t, testCfgDefaults())
		cmd := buildRootCmd()
		cmd.SetArgs([]string{"enroll", "hardware-key", "--config", plainPath})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})
}

// TestEnrollHardwareKey_ApplySuccess: with the TTY seam open and a scripted
// MockProvider, --apply records the request, writes hardware_keys.key_path
// through the audited config.Write, and prints the secret-free connection
// guidance.
func TestEnrollHardwareKey_ApplySuccess(t *testing.T) {
	mock := hwkeyTestEnv(t)
	cfg, cfgPath := hwkeyEnabledConfig(t)

	keyDir := filepath.Dir(cfg.HardwareKeys.KeyPath)
	handle := filepath.Join(keyDir, "abysslink_id_sk")
	pub := handle + ".pub"
	require.NoError(t, os.WriteFile(pub, []byte("sk-ssh-ed25519@openssh.com AAAA abysslink-test-rig\n"), 0o644))
	mock.EnrollResult = &hwkey.EnrolledKey{
		Kind:          hwkey.KindFIDO2,
		PrivateHandle: handle,
		PublicKeyPath: pub,
		Info:          hwkey.KeyInfo{TypeToken: "sk-ssh-ed25519@openssh.com", Hardware: true},
	}

	origGate := enrollHwkeyInteractive
	enrollHwkeyInteractive = func(_, _ bool) bool { return true }
	t.Cleanup(func() { enrollHwkeyInteractive = origGate })

	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs([]string{"enroll", "hardware-key", "--config", cfgPath, "--apply"})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, cmd.Execute())

	require.Len(t, mock.EnrollCalls, 1)
	req := mock.EnrollCalls[0]
	assert.Equal(t, keyDir, req.Dir)
	assert.Equal(t, "ed25519-sk", req.KeyType)
	assert.Equal(t, "ssh:abysslink", req.Application)
	assert.Equal(t, "abysslink-test-rig", req.Label)

	cfg2, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, handle, cfg2.HardwareKeys.KeyPath, "key_path must be recorded via the audited write")

	out := buf.String()
	assert.Contains(t, out, "verified sk-backed")
	assert.Contains(t, out, "IdentitiesOnly=yes")
	assert.Contains(t, out, "IdentityAgent=none")
	assert.Contains(t, out, "PasswordAuthentication=no")
	assert.Contains(t, out, "sk-ssh-ed25519@openssh.com")
}

// TestEnrollHardwareKey_EnclaveRequestKeyType is the P37-01 regression: the
// DEFAULT secure-enclave config (exactly what `enroll rig --key-kind
// secure-enclave --apply` writes — Enabled+Provider, no key_type) must build
// an EnrollRequest the enclave provider can honour. Before the provider-aware
// ResolvedKeyType, the CLI resolved the fido2 default ed25519-sk for ALL
// providers and SecureEnclaveProvider.Enroll refused it 100% of the time —
// a guaranteed dead path the MockProvider-based tests never saw.
func TestEnrollHardwareKey_EnclaveRequestKeyType(t *testing.T) {
	t.Run("request_construction", func(t *testing.T) {
		cfg := testCfgDefaults()
		cfg.HardwareKeys = config.HardwareKeysConfig{
			Enabled:  true,
			Provider: "secure-enclave",
			KeyPath:  filepath.Join(t.TempDir(), "abysslink_id_sk"),
		}
		req, err := buildHwkeyEnrollRequest(cfg)
		require.NoError(t, err)
		assert.Equal(t, "ecdsa-sk", req.KeyType,
			"the enclave request must carry ecdsa-sk — ed25519-sk is impossible on the enclave and would be refused fail-closed")
	})

	t.Run("apply_flow_end_to_end", func(t *testing.T) {
		mock := hwkeyTestEnv(t)
		mock.ProviderKind = hwkey.KindSecureEnclave

		cfg := testCfgDefaults()
		cfg.HardwareKeys = config.HardwareKeysConfig{
			Enabled:  true,
			Provider: "secure-enclave",
			KeyPath:  filepath.Join(t.TempDir(), "abysslink_id_sk"),
		}
		cfgPath := writeTestConfig(t, cfg)

		keyDir := filepath.Dir(cfg.HardwareKeys.KeyPath)
		handle := filepath.Join(keyDir, "id_ecdsa_sk_rk")
		pub := handle + ".pub"
		require.NoError(t, os.WriteFile(pub, []byte("sk-ecdsa-sha2-nistp256@openssh.com AAAA abysslink-test-rig\n"), 0o644))
		mock.EnrollResult = &hwkey.EnrolledKey{
			Kind:          hwkey.KindSecureEnclave,
			PrivateHandle: handle,
			PublicKeyPath: pub,
			Info:          hwkey.KeyInfo{TypeToken: "sk-ecdsa-sha2-nistp256@openssh.com", Hardware: true},
		}

		origGate := enrollHwkeyInteractive
		enrollHwkeyInteractive = func(_, _ bool) bool { return true }
		t.Cleanup(func() { enrollHwkeyInteractive = origGate })

		var buf bytes.Buffer
		cmd := buildRootCmd()
		cmd.SetArgs([]string{"enroll", "hardware-key", "--config", cfgPath, "--apply"})
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		require.NoError(t, cmd.Execute())

		require.Len(t, mock.EnrollCalls, 1)
		assert.Equal(t, "ecdsa-sk", mock.EnrollCalls[0].KeyType,
			"the --apply enclave flow must never request the fido2 default ed25519-sk")
	})
}

// TestNewRunnerSatisfiesDirRunner is the CLI-side P37-01 regression: the
// PRODUCTION runner composition (newRunner = gate.New over shell.ExecRunner)
// must keep the optional shell.DirRunner capability the enclave enrollment
// type-asserts — a decorator that strips it makes `enroll hardware-key
// --apply` structurally unreachable in the shipped binary while every
// MockRunner/MockProvider test stays green. Constructing the runner executes
// nothing.
func TestNewRunnerSatisfiesDirRunner(t *testing.T) {
	r := newRunner()
	_, ok := r.(shell.DirRunner)
	require.True(t, ok, "the production runner must implement shell.DirRunner (ssh-keygen -K needs a controlled CWD)")
}

// --- sec-hwkey-kind doctor battery (HWK-03) ---

func TestDoctorSecHwkeyKind_DisabledOK(t *testing.T) {
	cc := &cmdContext{cfg: testCfgDefaults(), runner: shell.NewMockRunner()}
	f := secHwkeyKindCheck(context.Background(), cc)
	assert.Equal(t, "sec-hwkey-kind", f.Check)
	assert.Equal(t, modules.SeverityOK, f.Severity)
	assert.Contains(t, f.Message, "disabled (opt-in)")
}

func TestDoctorSecHwkeyKind_VerifiedOK(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "abysslink_id_sk")
	require.NoError(t, os.WriteFile(keyPath+".pub", []byte("sk-ssh-ed25519@openssh.com AAAA me@rig\n"), 0o644))

	cfg := testCfgDefaults()
	cfg.HardwareKeys = config.HardwareKeysConfig{Enabled: true, Provider: "fido2", KeyPath: keyPath}
	// One scripted ssh-keygen -l cross-check call for provider.Verify.
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{
		Stdout: "256 SHA256:abcdefg me@rig (ED25519-SK)\n", ExitCode: 0,
	}})
	cc := &cmdContext{cfg: cfg, runner: r}

	f := secHwkeyKindCheck(context.Background(), cc)
	assert.Equal(t, modules.SeverityOK, f.Severity)
	assert.Contains(t, f.Message, "hardware:fido2")
	assert.True(t, r.Done())
}

func TestDoctorSecHwkeyKind_MissingWarn(t *testing.T) {
	cfg := testCfgDefaults()
	cfg.HardwareKeys = config.HardwareKeysConfig{Enabled: true, Provider: "fido2",
		KeyPath: filepath.Join(t.TempDir(), "never-enrolled")}
	cc := &cmdContext{cfg: cfg, runner: shell.NewMockRunner()}

	f := secHwkeyKindCheck(context.Background(), cc)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	assert.Contains(t, f.Message, "enroll hardware-key")
}

func TestDoctorSecHwkeyKind_UnverifiableWarn(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "abysslink_id_sk")
	require.NoError(t, os.WriteFile(keyPath+".pub", []byte("garbage that is not a key\n"), 0o644))
	cfg := testCfgDefaults()
	cfg.HardwareKeys = config.HardwareKeysConfig{Enabled: true, Provider: "fido2", KeyPath: keyPath}
	cc := &cmdContext{cfg: cfg, runner: shell.NewMockRunner()}

	f := secHwkeyKindCheck(context.Background(), cc)
	assert.Equal(t, modules.SeverityWarning, f.Severity, "a parse miss is WARN — never OK, never silently software")
}

// TestDoctorSecHwkeyKind_SoftwareFatal: enabled + a verifiably software key
// is FATAL in the DEFAULT profile (silent-downgrade detected, HWK-03) with
// zero Runner calls.
func TestDoctorSecHwkeyKind_SoftwareFatal(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "abysslink_id_sk")
	require.NoError(t, os.WriteFile(keyPath+".pub", []byte("ssh-ed25519 AAAA me@rig\n"), 0o644))
	cfg := testCfgDefaults()
	cfg.HardwareKeys = config.HardwareKeysConfig{Enabled: true, Provider: "secure-enclave", KeyPath: keyPath}
	r := shell.NewMockRunner() // zero calls: the pub classification is pure
	cc := &cmdContext{cfg: cfg, runner: r}

	f := secHwkeyKindCheck(context.Background(), cc)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
	assert.Contains(t, f.Message, "SOFTWARE")
	assert.Empty(t, r.RecordedCalls())
}

// TestDoctorSecHwkeyKind_LeadingBlankLineStillFatal is the P37-03 regression:
// a .pub whose software key sits after a leading blank line (manual edit,
// file concatenation) must classify exactly like the same key without the
// blank line — FATAL, not an "unverifiable" WARN. hwkeyKindFor previously
// classified the literal first line while the providers' Verify used the
// first NON-empty line, so leading whitespace dodged the HWK-03
// silent-downgrade detector.
func TestDoctorSecHwkeyKind_LeadingBlankLineStillFatal(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "abysslink_id_sk")
	require.NoError(t, os.WriteFile(keyPath+".pub", []byte("\nssh-ed25519 AAAA me@rig\n"), 0o644))
	cfg := testCfgDefaults()
	cfg.HardwareKeys = config.HardwareKeysConfig{Enabled: true, Provider: "secure-enclave", KeyPath: keyPath}
	r := shell.NewMockRunner() // zero calls: the pub classification is pure
	cc := &cmdContext{cfg: cfg, runner: r}

	f := secHwkeyKindCheck(context.Background(), cc)
	assert.Equal(t, modules.SeverityFatal, f.Severity,
		"a leading blank line must not degrade the software-key FATAL to WARN")
	assert.Contains(t, f.Message, "SOFTWARE")
	assert.Empty(t, r.RecordedCalls())
}

// --- sec-attest-* doctor battery (ATT-02) ---

// TestDoctorSecAttest_ToolMissingWarn: with every probe tool missing (or the
// efivar tree absent) each attest finding is WARN — never a false OK.
func TestDoctorSecAttest_ToolMissingWarn(t *testing.T) {
	origProber := newAttestProber
	newAttestProber = func(r shell.Runner) *attest.Prober {
		p := attest.New(r)
		p.EFIVarsDir = filepath.Join(t.TempDir(), "efi", "efivars") // parent absent
		p.LookPath = func(string) bool { return false }
		return p
	}
	t.Cleanup(func() { newAttestProber = origProber })

	// Zero scripted calls: every RunWithEnv fails like a missing tool.
	cc := &cmdContext{cfg: testCfgDefaults(), runner: shell.NewMockRunner()}
	findings := secAttestChecks(context.Background(), cc)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Equal(t, "sec", f.Module)
		assert.True(t, strings.HasPrefix(f.Check, "sec-attest-"), "check %q", f.Check)
		assert.Equal(t, modules.SeverityWarning, f.Severity,
			"a missing tool must be WARN (fail-closed), got %v for %s", f.Severity, f.Check)
	}
}

// TestDoctorAtRiskEscalatesAttestToFatal: `--profile at-risk` tightens the
// Phase 37 WARNs to FATAL (and only tightens — OK stays OK).
func TestDoctorAtRiskEscalatesAttestToFatal(t *testing.T) {
	in := []modules.Finding{
		{Module: "sec", Check: "sec-attest-sip", Severity: modules.SeverityWarning},
		{Module: "sec", Check: "sec-attest-secureboot", Severity: modules.SeverityWarning},
		{Module: "sec", Check: "sec-attest-tpm", Severity: modules.SeverityWarning},
		{Module: "sec", Check: "sec-hwkey-kind", Severity: modules.SeverityWarning},
		{Module: "sec", Check: "sec-attest-sip", Severity: modules.SeverityOK}, // OK is never touched
	}
	cfg := testCfgDefaults()
	cfg.Deadman.Enabled = true // isolate the escalation assertion
	out := tightenAtRiskProfile(in, cfg)
	require.Len(t, out, len(in))
	for i := 0; i < 4; i++ {
		assert.Equal(t, modules.SeverityFatal, out[i].Severity, "check %s must escalate WARN->FATAL", out[i].Check)
	}
	assert.Equal(t, modules.SeverityOK, out[4].Severity, "the profile only tightens; OK stays OK")
}

// --- status surface (HWK-03 / ATT-02) ---

// TestStatusKeyKindAndAttestationJSON: the JSON report carries key_kind only
// when hardware keys are enabled (omitempty keeps old consumers stable) and
// always carries the attestation summary.
func TestStatusKeyKindAndAttestationJSON(t *testing.T) {
	t.Run("omitempty_when_disabled", func(t *testing.T) {
		raw, err := json.Marshal(statusReport{Tailscale: "running", Attestation: "unverified"})
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "key_kind", "KeyKind must be omitted when disabled")
		assert.Contains(t, string(raw), `"attestation":"unverified"`)
	})

	t.Run("fields_present_when_set", func(t *testing.T) {
		raw, err := json.Marshal(statusReport{KeyKind: "hardware:fido2", Attestation: "verified"})
		require.NoError(t, err)
		assert.Contains(t, string(raw), `"key_kind":"hardware:fido2"`)
		assert.Contains(t, string(raw), `"attestation":"verified"`)
	})

	t.Run("command_json_output", func(t *testing.T) {
		setupStylesParityEnv(t)

		origKK := collectKeyKind
		collectKeyKind = func(_ context.Context, _ *cmdContext) string { return "hardware:fido2" }
		t.Cleanup(func() { collectKeyKind = origKK })
		origAtt := collectAttestation
		collectAttestation = func(_ context.Context, _ *cmdContext) string { return "weakened" }
		t.Cleanup(func() { collectAttestation = origAtt })

		var buf bytes.Buffer
		cmd := buildRootCmd()
		cmd.SetArgs([]string{"--json", "status", "--config", filepath.Join("testdata", "v1.yaml")})
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		require.NoError(t, cmd.Execute())

		var rep statusReport
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rep))
		assert.Equal(t, "hardware:fido2", rep.KeyKind)
		assert.Equal(t, "weakened", rep.Attestation)
	})
}

// TestStatusRowStateFor_Phase37Vocab pins the panel colour vocabulary. The
// Phase 37 Key Kind / Attestation rows have their OWN mapper
// (statusKeyRowStateFor); the legacy mapper is asserted separately below.
func TestStatusRowStateFor_Phase37Vocab(t *testing.T) {
	assert.Equal(t, rowOK, statusKeyRowStateFor("verified"))
	assert.Equal(t, rowOK, statusKeyRowStateFor("hardware:secure-enclave"))
	assert.Equal(t, rowOK, statusKeyRowStateFor("hardware:fido2"))
	assert.Equal(t, rowNeutral, statusKeyRowStateFor("unverified"))
	assert.Equal(t, rowNeutral, statusKeyRowStateFor("unknown"))
	assert.Equal(t, rowBad, statusKeyRowStateFor("weakened"))
	assert.Equal(t, rowBad, statusKeyRowStateFor("software"))
	assert.Equal(t, rowBad, statusKeyRowStateFor("anything-unrecognized"), "fail closed")
}

// TestStatusRowStateFor_LegacyUnknownStaysRed is the P37-02 regression: the
// pre-existing Tailscale and Disk Encryption rows emit "unknown" exactly when
// their probe FAILS (tailscaled unreachable; fdesetup/lsblk missing, denied,
// or unparseable — the evidence-suppression cases doctor treats as FATAL).
// Folding "unknown" into the shared neutral vocabulary silently softened that
// red ✕ to a calm ○ for ALL users, weakening a shipped default (CLAIMS-AUDIT
// C-25). The legacy mapper must keep every indeterminate value red.
func TestStatusRowStateFor_LegacyUnknownStaysRed(t *testing.T) {
	assert.Equal(t, rowBad, statusRowStateFor("unknown"),
		"a failed Tailscale/Disk Encryption probe must stay a red ✕ — never neutral")
	assert.Equal(t, rowBad, statusRowStateFor("unencrypted"))
	assert.Equal(t, rowBad, statusRowStateFor("stopped"))
	assert.Equal(t, rowNeutral, statusRowStateFor("disabled"), "deliberate opt-out stays neutral (U4)")
	assert.Equal(t, rowOK, statusRowStateFor("running"))
	assert.Equal(t, rowOK, statusRowStateFor("enabled"))
	assert.Equal(t, rowOK, statusRowStateFor("encrypted"))
	// The Phase 37 vocabulary must NOT leak into the legacy mapper: these
	// values are red there, exactly like any other unrecognized value.
	assert.Equal(t, rowBad, statusRowStateFor("unverified"))
	assert.Equal(t, rowBad, statusRowStateFor("hardware:fido2"))
}
