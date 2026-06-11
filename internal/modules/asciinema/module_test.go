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

package asciinema

import (
	"context"
	"os"
	"path/filepath"
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
	cfg.Modules.Asciinema.Enabled = true
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
	cfg.Modules.Asciinema.Enabled = false
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDetect_CloudUploadConfigured_Warning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "asciinema")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgPath := filepath.Join(cfgDir, "config")
	require.NoError(t, os.WriteFile(cfgPath, []byte("[api]\nurl = https://asciinema.org\n"), 0o600))

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "no_cloud_upload", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_Installed_NoConfig_NoFindings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApply_NilAudit_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
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

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	cfgPath := filepath.Join(dir, "asciinema", "config")
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "[api]")
}

func TestApply_SkipsWriteIfConfigExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "asciinema")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgPath := filepath.Join(cfgDir, "config")
	original := []byte("# user config\n")
	require.NoError(t, os.WriteFile(cfgPath, original, 0o600))

	auditLog := filepath.Join(dir, "audit.log")
	a := audit.New(auditLog)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, original, data)
}

// TestApply_DisablesCloudUploadInExistingConfig is the W6 regression test:
// when an EXISTING config actively points uploads at asciinema.org, Apply
// must remediate (comment the url line out under audit) rather than skip —
// Plan promises "configure asciinema to disable cloud uploads".
func TestApply_DisablesCloudUploadInExistingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "asciinema")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgPath := filepath.Join(cfgDir, "config")
	require.NoError(t, os.WriteFile(cfgPath,
		[]byte("[api]\nurl = https://asciinema.org\ntoken = abc\n"), 0o600))

	a := audit.New(filepath.Join(dir, "audit.log"))
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	content := string(data)
	assert.False(t, hasActiveCloudUploadURL(content), "active upload URL must be disabled")
	assert.Contains(t, content, "token = abc", "unrelated user config must be preserved")

	// Convergence: Detect on the patched config no longer flags it, and a
	// second Apply leaves the file untouched.
	findings, err := m2Detect(t, dir)
	require.NoError(t, err)
	for _, f := range findings {
		assert.NotEqual(t, "no_cloud_upload", f.Check, "patched config must not re-trigger the finding")
	}
}

// m2Detect runs Detect with a fresh module instance against the same temp env.
func m2Detect(t *testing.T, _ string) ([]modules.Finding, error) {
	t.Helper()
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	return m.Detect(context.Background())
}

// TestDetect_DefaultConfigNotFlagged: the privacy config Apply writes mentions
// the asciinema.org URL only in comments — Detect must not flag it (the old
// substring check did, making the module non-convergent).
func TestDetect_DefaultConfigNotFlagged(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "asciinema")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "config"), []byte(asciinemaConfig), 0o600))

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "asciinema 2.3.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "the module's own default config must never be flagged")
}

func TestHasActiveCloudUploadURL(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"active url", "[api]\nurl = https://asciinema.org\n", true},
		{"active url with spaces", "[api]\n  url   =   https://asciinema.org  \n", true},
		{"commented semicolon", "[api]\n; url = https://asciinema.org\n", false},
		{"commented hash", "[api]\n# url = https://asciinema.org\n", false},
		{"comment mentioning url", "; Set url = https://asciinema.org to enable\n", false},
		{"self-hosted url", "[api]\nurl = https://rec.example.com\n", false},
		{"empty", "", false},
		{"default config", asciinemaConfig, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hasActiveCloudUploadURL(tc.content))
		})
	}
}

func TestApply_Disabled_NoOp(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Asciinema.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	require.NoError(t, m.Apply(context.Background()))
}

// TestVerify_ReturnsNil: Verify must not re-run Detect — runner.Doctor calls
// both, and delegating would double every finding per doctor pass (W4/NET-18).
func TestVerify_ReturnsNil(t *testing.T) {
	r := shell.NewMockRunner() // Verify must not touch the runner
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done())
}
