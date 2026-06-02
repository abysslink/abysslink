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

package atuin

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Atuin.Enabled = true
	return cfg
}

func TestDetect_NotInstalled_Warning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "installed", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_Disabled_NoFindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Atuin.Enabled = false
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDetect_CloudSyncConfigured_Warning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "atuin")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgPath := filepath.Join(cfgDir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("[sync]\nsync_address = \"https://api.atuin.sh\"\n"), 0o600))

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "no_cloud_sync", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_Installed_NoConfig_NoFindings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApply_NilAudit_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: nil})
	err := m.Apply(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit not available")
}

func TestApply_WritesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	auditLog := filepath.Join(dir, "audit.log")
	a := audit.New(auditLog)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	cfgPath := filepath.Join(dir, "atuin", "config.toml")
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "[sync]")
	assert.Contains(t, string(data), `sync_address = ""`)
}

func TestApply_SkipsWriteIfConfigExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "atuin")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgPath := filepath.Join(cfgDir, "config.toml")
	original := []byte("# user config\n")
	require.NoError(t, os.WriteFile(cfgPath, original, 0o600))

	auditLog := filepath.Join(dir, "audit.log")
	a := audit.New(auditLog)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, original, data)
}

func TestApply_Disabled_NoOp(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Atuin.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	require.NoError(t, m.Apply(context.Background()))
}

func TestVerify_DelegatesToDetect(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "installed", findings[0].Check)
}

func TestApply_WritesShellRC_Zsh(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")

	auditLog := filepath.Join(dir, "audit.log")
	a := audit.New(auditLog)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	data, err := os.ReadFile(filepath.Join(dir, ".zshrc"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `eval "$(atuin init zsh)"`)
}

func TestApply_WritesShellRC_Bash(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/bash")

	auditLog := filepath.Join(dir, "audit.log")
	a := audit.New(auditLog)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	data, err := os.ReadFile(filepath.Join(dir, ".bashrc"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `eval "$(atuin init bash)"`)
}

// countingAudit wraps audit.AuditWriter to count WriteFile calls per path so
// the idempotency test can assert the shell-rc line is written at most once.
type countingAudit struct {
	inner  *audit.Audit
	counts map[string]int
}

func (c *countingAudit) WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error {
	c.counts[path]++
	return c.inner.WriteFile(path, content, perm, dryRun)
}

func TestApply_Idempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")

	rcPath := filepath.Join(dir, ".zshrc")
	require.NoError(t, os.WriteFile(rcPath, []byte("# user rc\neval \"$(atuin init zsh)\"\n"), 0o600))

	a := &countingAudit{inner: audit.New(filepath.Join(dir, "audit.log")), counts: map[string]int{}}

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	assert.Zero(t, a.counts[rcPath], "shell rc must not be rewritten when the init line is already present")
}

func TestKeyPath_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-specific path layout")
	}
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", dir)
	assert.Equal(t, filepath.Join(dir, ".local", "share", "atuin", "key"), KeyPath())

	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "xdgdata"))
	assert.Equal(t, filepath.Join(dir, "xdgdata", "atuin", "key"), KeyPath())
}
