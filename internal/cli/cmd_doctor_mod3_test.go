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

import (
	"context"
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upsnapEnabledCfg returns a config with the upsnap module enabled.
func upsnapEnabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Upsnap.Enabled = true
	return cfg
}

// TestDoctorWolApplyGate_Warn verifies the wol-apply-gate advisory is present
// when upsnap is enabled and is graded WARN — a pure structural advisory must
// never make a healthy rig exit 2 forever (review W7).
func TestDoctorWolApplyGate_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), upsnapEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "wol-apply-gate")
	require.True(t, ok, "wol-apply-gate must be present when upsnap is enabled")
	assert.Equal(t, modules.SeverityWarning, f.Severity,
		"unconditional advisory must be WARN, not FATAL (W7)")
}

// TestDoctorUpSnapBind_Warn verifies the upsnap-bind WARN finding is present.
func TestDoctorUpSnapBind_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), upsnapEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "upsnap-bind")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// TestDoctorUpSnapNoPublic_Warn verifies the upsnap-no-public WARN finding is present.
func TestDoctorUpSnapNoPublic_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), upsnapEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "upsnap-no-public")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// TestDoctorMod3_DisabledNoFindings verifies that a disabled upsnap module
// yields no findings.
func TestDoctorMod3_DisabledNoFindings(t *testing.T) {
	cfg := config.Defaults() // all mod3 modules disabled by default
	findings := mod3DoctorFindings(context.Background(), cfg, shell.NewMockRunner())
	assert.Empty(t, findings)
}

// atuinEnabledCfg returns a config with the atuin module enabled.
func atuinEnabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Atuin.Enabled = true
	return cfg
}

// asciinemaEnabledCfg returns a config with the asciinema module enabled.
func asciinemaEnabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Asciinema.Enabled = true
	return cfg
}

// TestDoctorAtuinBind_Warn verifies the atuin-bind advisory is present when
// atuin is enabled and is graded WARN (structural advisory, review W7).
func TestDoctorAtuinBind_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), atuinEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "atuin-bind")
	require.True(t, ok, "atuin-bind must be present when atuin is enabled")
	assert.Equal(t, modules.SeverityWarning, f.Severity,
		"unconditional advisory must be WARN, not FATAL (W7)")
}

// TestDoctorAtuinKeyBackedUp_Warn verifies the atuin-key-backed-up WARN finding
// is present when atuin is enabled (both key-present and key-absent are WARN).
func TestDoctorAtuinKeyBackedUp_Warn(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir) // point KeyPath at a temp dir with no key file

	findings := mod3DoctorFindings(context.Background(), atuinEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "atuin-key-backed-up")
	require.True(t, ok, "atuin-key-backed-up must be present when atuin is enabled")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// sandboxEnabledCfg returns a config with the sandbox module enabled.
func sandboxEnabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Sandbox.Enabled = true
	return cfg
}

// TestDoctorSandboxLandlockSupported_Warn verifies the
// sandbox-landlock-supported finding is present when the sandbox module is
// enabled. On non-Linux (and Linux < 5.13) it is WARN; on a Landlock-capable
// Linux kernel it is OK. The finding must always be present either way.
func TestDoctorSandboxLandlockSupported_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), sandboxEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "sandbox-landlock-supported")
	require.True(t, ok, "sandbox-landlock-supported must be present when sandbox is enabled")
	if runtime.GOOS == "linux" {
		assert.Contains(t, []modules.Severity{modules.SeverityOK, modules.SeverityWarning}, f.Severity)
	} else {
		assert.Equal(t, modules.SeverityWarning, f.Severity, "Landlock is Linux-only — must WARN on non-Linux")
	}
}

// TestDoctorAsciinemaRecWarning_Warn verifies the asciinema-rec-warning
// advisory is present when asciinema is enabled and is graded WARN
// (structural advisory, review W7).
func TestDoctorAsciinemaRecWarning_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), asciinemaEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "asciinema-rec-warning")
	require.True(t, ok, "asciinema-rec-warning must be present when asciinema is enabled")
	assert.Equal(t, modules.SeverityWarning, f.Severity,
		"unconditional advisory must be WARN, not FATAL (W7)")
}

// TestDoctorMod3_NoFatalsForHealthyEnabledModules is the W7 regression test:
// enabling upsnap/atuin/asciinema on a healthy rig must not introduce any
// FATAL finding (doctor would otherwise permanently exit 2).
func TestDoctorMod3_NoFatalsForHealthyEnabledModules(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Upsnap.Enabled = true
	cfg.Modules.Atuin.Enabled = true
	cfg.Modules.Asciinema.Enabled = true
	findings := mod3DoctorFindings(context.Background(), cfg, shell.NewMockRunner())
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.NotEqual(t, modules.SeverityFatal, f.Severity,
			"mod3 advisory %q must not be FATAL on a healthy rig (W7)", f.Check)
	}
}

// netbirdBackendCfg returns a config with the NetBird backend selected.
func netbirdBackendCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	return cfg
}

// TestDoctorNbPostureActive_Warn verifies the nb-posture-active WARN finding is
// present when the NetBird backend is configured but the API key is unset
// (cannot reach the API to count posture checks).
func TestDoctorNbPostureActive_Warn(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "") // no key → cannot check posture status

	findings := mod3DoctorFindings(context.Background(), netbirdBackendCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "nb-posture-active")
	require.True(t, ok, "nb-posture-active must be present when NetBird backend is configured")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// TestDoctorNbPostureActive_AbsentForNonNetBird verifies the finding is NOT
// emitted for non-NetBird backends.
func TestDoctorNbPostureActive_AbsentForNonNetBird(t *testing.T) {
	cfg := config.Defaults() // backend.type defaults to tailscale
	findings := mod3DoctorFindings(context.Background(), cfg, shell.NewMockRunner())
	_, ok := findFinding(findings, "nb-posture-active")
	assert.False(t, ok, "nb-posture-active must not be emitted for non-NetBird backends")
}
