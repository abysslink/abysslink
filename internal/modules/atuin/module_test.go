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
	"strings"
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

// TestApply_PreservesShellRCPerms verifies WR-04: appending the atuin init line
// to a pre-existing 0o644 shell rc must NOT narrow it to 0o600. The user's
// existing dotfile permissions are preserved.
func TestApply_PreservesShellRCPerms(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")

	rcPath := filepath.Join(dir, ".zshrc")
	require.NoError(t, os.WriteFile(rcPath, []byte("# user rc\n"), 0o644)) //nolint:gosec // G306: test fixture deliberately created world-readable (0o644, the conventional shell-rc mode) to verify the perm is preserved, not narrowed

	a := audit.New(filepath.Join(dir, "audit.log"))
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	fi, err := os.Stat(rcPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "existing shell rc mode must be preserved, not narrowed")

	data, err := os.ReadFile(rcPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), `eval "$(atuin init zsh)"`)
}

// TestApply_NewShellRCDefaultPerms verifies that when no rc file exists, the
// freshly-created one gets the conventional 0o644 default for shell init files.
func TestApply_NewShellRCDefaultPerms(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/bash")

	a := audit.New(filepath.Join(dir, "audit.log"))
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	fi, err := os.Stat(filepath.Join(dir, ".bashrc"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "new shell rc must use the conventional 0o644 default")
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

// Update delegates to the inner writer's cross-process read-modify-write so
// *countingAudit still satisfies audit.AuditWriter; the counting test exercises
// WriteFile only.
func (c *countingAudit) Update(ctx context.Context, path string, perm os.FileMode, content func() ([]byte, error)) error {
	return c.inner.Update(ctx, path, perm, content)
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

// TestDetect_CommentedCloudSync_NoFinding is the W8 regression test: stock
// atuin configs ship `# sync_address = "https://api.atuin.sh"` commented out —
// that must NOT be flagged as active cloud sync (it caused a perpetual WARN).
func TestDetect_CommentedCloudSync_NoFinding(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "atuin")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	stock := "## where to sync to\n# sync_address = \"https://api.atuin.sh\"\n\n[history]\nfilter_mode = \"global\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(stock), 0o600))

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "commented-out default must not be flagged (W8)")
}

func TestConfigEnablesCloudSync(t *testing.T) {
	assert.False(t, configEnablesCloudSync(`# sync_address = "https://api.atuin.sh"`))
	assert.False(t, configEnablesCloudSync("  ## sync_address = \"https://api.atuin.sh\"\n"))
	assert.True(t, configEnablesCloudSync(`sync_address = "https://api.atuin.sh"`))
	assert.True(t, configEnablesCloudSync("[sync]\nsync_address = \"https://api.atuin.sh\" # default\n"))
	assert.False(t, configEnablesCloudSync(`sync_address = "https://atuin.example.org"`))
	assert.False(t, configEnablesCloudSync(""))
}

// TestApply_RewritesCloudSyncConfig is the W8 convergence test: an existing
// config that actively syncs with the public cloud must be rewritten by Apply
// (audit-backed) to local-only mode — previously Apply skipped any existing
// file, so the planned remediation never executed and the WARN never cleared.
func TestApply_RewritesCloudSyncConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")

	cfgDir := filepath.Join(dir, "atuin")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgPath := filepath.Join(cfgDir, "config.toml")
	userCfg := "## my atuin config\nauto_sync = true\n\n[sync]\nsync_address = \"https://api.atuin.sh\"\n\n[keys]\nscroll_exits = false\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(userCfg), 0o600))

	a := audit.New(filepath.Join(dir, "audit.log"))
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	content := string(data)
	assert.NotContains(t, content, "api.atuin.sh", "cloud sync address must be blanked")
	assert.Contains(t, content, `sync_address = ""`)
	assert.Contains(t, content, "auto_sync = false", "auto_sync must be forced off")
	assert.Contains(t, content, "secrets_filter = true", "secrets_filter must be forced on")
	assert.Contains(t, content, "scroll_exits = false", "user customisations must be preserved")
	assert.NotContains(t, content, "auto_sync = true")

	// Convergence: a second Detect on the rewritten config must be clean.
	r2 := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m2 := New(modules.Deps{Cfg: enabledCfg(), Runner: r2, Audit: a})
	findings, err := m2.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "Apply must converge the no_cloud_sync finding (W8)")
}

// TestRemediateCloudSync_PrependsTopLevelKeys asserts missing keys are added
// BEFORE the first [section] — appending at EOF would land them inside the
// last TOML table.
func TestRemediateCloudSync_PrependsTopLevelKeys(t *testing.T) {
	in := "[sync]\nsync_address = \"https://api.atuin.sh\"\n"
	out := remediateCloudSync(in)
	idxAuto := strings.Index(out, "auto_sync = false")
	idxSection := strings.Index(out, "[sync]")
	require.GreaterOrEqual(t, idxAuto, 0)
	require.GreaterOrEqual(t, idxSection, 0)
	assert.Less(t, idxAuto, idxSection, "added top-level keys must precede the first [section]")
	assert.Contains(t, out, `sync_address = ""`)
}

// TestApply_GeneratedConfigIsLocalOnly pins the hardened defaults of the
// freshly-generated config: auto_sync off, secrets_filter on, empty
// sync_address.
func TestApply_GeneratedConfigIsLocalOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)

	a := audit.New(filepath.Join(dir, "audit.log"))
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	data, err := os.ReadFile(filepath.Join(dir, "atuin", "config.toml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "auto_sync = false")
	assert.Contains(t, string(data), "secrets_filter = true")
	assert.Contains(t, string(data), `sync_address = ""`)
}

// TestPlan_NoPhantomWriteAction: with atuin installed and a clean existing
// config, Plan must emit NO actions — the old unconditional "write atuin
// config" action promised a write that Apply never performed (W8 UX).
func TestPlan_NoPhantomWriteAction(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "atuin")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("# user config\n"), 0o600))

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, actions, "clean existing config: dry-run must not promise a write")
}

// TestPlan_MissingConfig_EmitsWriteAction: the write action remains when the
// config file genuinely does not exist.
func TestPlan_MissingConfig_EmitsWriteAction(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "atuin 18.0.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Description, "write atuin config")
}
