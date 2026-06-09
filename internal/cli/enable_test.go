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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSetModuleEnabled(t *testing.T) {
	cfg := config.Defaults()

	require.NoError(t, setModuleEnabled(cfg, "claudecode", true))
	assert.True(t, cfg.ClaudeCode.Enabled)

	require.NoError(t, setModuleEnabled(cfg, "code-server", true))
	assert.True(t, cfg.Modules.CodeServer.Enabled)

	// Alias resolves to the same field.
	require.NoError(t, setModuleEnabled(cfg, "et", true))
	assert.True(t, cfg.Modules.EternalTerminal.Enabled)

	require.NoError(t, setModuleEnabled(cfg, "ttyd", false))
	assert.False(t, cfg.Modules.Ttyd.Enabled)

	assert.Error(t, setModuleEnabled(cfg, "nonsense", true))
}

// writeToggleCfg writes a valid config (optionally with claudecode pre-enabled)
// and returns its path.
func writeToggleCfg(t *testing.T, claudecodeEnabled bool) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	cfg.ClaudeCode.Enabled = claudecodeEnabled
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// runToggle executes the given enable/disable args via the real root command.
func runToggle(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

// TestEnableCmd_DryRunDefault_NoWrite asserts the CLI-02 gate: without --apply,
// `abysslink enable <mod>` prints a [plan] preview and does NOT write config.
func TestEnableCmd_DryRunDefault_NoWrite(t *testing.T) {
	cfgPath := writeToggleCfg(t, false)
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	out, err := runToggle(t, "enable", "claudecode", "--config", cfgPath)
	require.NoError(t, err)
	assert.Contains(t, out, "[plan] would enable", "dry-run must print a plan preview")

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "dry-run must not modify config")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.False(t, cfg.ClaudeCode.Enabled, "module must remain disabled without --apply")
}

// TestEnableCmd_Apply_WritesConfig asserts that --apply persists the toggle.
func TestEnableCmd_Apply_WritesConfig(t *testing.T) {
	cfgPath := writeToggleCfg(t, false)
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // keep audit/backup writes inside the test sandbox

	out, err := runToggle(t, "enable", "claudecode", "--config", cfgPath, "--apply")
	require.NoError(t, err)
	assert.Contains(t, out, "enabled", "apply must confirm the change")
	assert.NotContains(t, out, "[plan]", "apply output must not be a plan preview")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.True(t, cfg.ClaudeCode.Enabled, "--apply must persist the toggle")
}

// TestDisableCmd_DryRunDefault_NoWrite asserts the CLI-02 gate for disable.
func TestDisableCmd_DryRunDefault_NoWrite(t *testing.T) {
	cfgPath := writeToggleCfg(t, true)

	out, err := runToggle(t, "disable", "claudecode", "--config", cfgPath)
	require.NoError(t, err)
	assert.Contains(t, out, "[plan] would disable", "dry-run must print a plan preview")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.True(t, cfg.ClaudeCode.Enabled, "module must remain enabled without --apply")
}

// TestEnableCmd_DryRunApplyMutuallyExclusive asserts CLI-09: passing both
// --dry-run and --apply is rejected with a clear error.
func TestEnableCmd_DryRunApplyMutuallyExclusive(t *testing.T) {
	cfgPath := writeToggleCfg(t, false)

	_, err := runToggle(t, "enable", "claudecode", "--config", cfgPath, "--dry-run", "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
