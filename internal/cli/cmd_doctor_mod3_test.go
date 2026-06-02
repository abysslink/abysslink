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

// TestDoctorWolApplyGate_Fatal verifies the wol-apply-gate FATAL finding is
// present when upsnap is enabled.
func TestDoctorWolApplyGate_Fatal(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), upsnapEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "wol-apply-gate")
	require.True(t, ok, "wol-apply-gate must be present when upsnap is enabled")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
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

// TestDoctorAtuinBind_Fatal verifies the atuin-bind FATAL finding is present
// when atuin is enabled.
func TestDoctorAtuinBind_Fatal(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), atuinEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "atuin-bind")
	require.True(t, ok, "atuin-bind must be present when atuin is enabled")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
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

// TestDoctorAsciinemaRecWarning_Fatal verifies the asciinema-rec-warning FATAL
// finding is present when asciinema is enabled.
func TestDoctorAsciinemaRecWarning_Fatal(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), asciinemaEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "asciinema-rec-warning")
	require.True(t, ok, "asciinema-rec-warning must be present when asciinema is enabled")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}
