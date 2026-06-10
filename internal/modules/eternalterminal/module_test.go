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

package eternalterminal

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPlatform is a no-op platform implementation for unit tests.
type mockPlatform struct {
	installErr error
	serviceErr error
	installed  []string
	services   []platform.ServiceSpec
}

func (p *mockPlatform) OS() string                              { return "linux" }
func (p *mockPlatform) Distro() platform.Distro                 { return platform.DistroUnknown }
func (p *mockPlatform) PackageManager() platform.PackageManager { return platform.PkgApt }
func (p *mockPlatform) InstallPackage(_ context.Context, name string) error {
	p.installed = append(p.installed, name)
	return p.installErr
}
func (p *mockPlatform) RemovePackage(_ context.Context, _ string) error { return nil }
func (p *mockPlatform) ServiceInstall(_ context.Context, spec platform.ServiceSpec) error {
	p.services = append(p.services, spec)
	return p.serviceErr
}
func (p *mockPlatform) ServiceUninstall(_ context.Context, _ string) error { return nil }
func (p *mockPlatform) ServiceStart(_ context.Context, _ string) error     { return nil }
func (p *mockPlatform) ServiceStop(_ context.Context, _ string) error      { return nil }
func (p *mockPlatform) ServiceStatus(_ context.Context, _ string) (platform.ServiceStatus, error) {
	return platform.ServiceUnknown, nil
}
func (p *mockPlatform) DiskEncryptionStatus(_ context.Context) (platform.DiskState, error) {
	return platform.DiskUnknown, nil
}
func (p *mockPlatform) Firewall() platform.FirewallController                       { return nil }
func (p *mockPlatform) KeepAwake(_ context.Context, _ platform.KeepAwakeMode) error { return nil }

// enabledCfg returns a config with the eternal-terminal module enabled.
func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.EternalTerminal.Enabled = true
	return cfg
}

func TestDetect_Disabled_NilFindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.EternalTerminal.Enabled = false
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done(), "no shell calls expected when disabled")
}

func TestDetect_ETClientNotFound_FatalFinding(t *testing.T) {
	// et --version → not found; etserver --version → not found; service unit → OS-dependent warning.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}}, // et
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}}, // etserver
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	// At minimum: et_client_installed + et_server_installed + et_service_unit_installed.
	require.GreaterOrEqual(t, len(findings), 2)

	checks := map[string]bool{}
	for _, f := range findings {
		checks[f.Check] = true
	}
	assert.True(t, checks["et_client_installed"], "must report missing et client")
	assert.True(t, checks["et_server_installed"], "must report missing etserver")
}

func TestDetect_ETClientMissing_FatalSeverity(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}}, // et
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}}, // etserver
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	for _, f := range findings {
		if f.Check == "et_client_installed" || f.Check == "et_server_installed" {
			assert.Equal(t, modules.SeverityFatal, f.Severity)
		}
	}
}

func TestDetect_ServiceUnitMissing_WarningSeverity(t *testing.T) {
	// Both binaries present, service unit absent.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "et version 6.4.9\n"}},       // et
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "etserver version 6.4.9\n"}}, // etserver
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	// The service unit check is always OS-dependent; in a test environment the
	// plist / unit file is not present, so expect a warning finding.
	require.Len(t, findings, 1)
	assert.Equal(t, "et_service_unit_installed", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestPlan_Disabled_Nil(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.EternalTerminal.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, actions)
}

func TestPlan_ETClientMissing_ReturnsInstallAction(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}}, // et
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}}, // etserver
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.NotEmpty(t, actions)

	checks := map[string]bool{}
	for _, a := range actions {
		checks[a.Description] = true
		assert.Equal(t, "eternal-terminal", a.Module)
	}
	// ACL grant action is always appended.
	hasACL := false
	for _, a := range actions {
		if a.Description != "" && len(a.Description) > 0 {
			if a.Description == "grant ACL tcp/2022 for eternal-terminal in Tailscale policy" {
				hasACL = true
			}
		}
	}
	assert.True(t, hasACL, "Plan must always include an ACL grant action")
}

func TestPlan_Enabled_AlwaysIncludesACLAction(t *testing.T) {
	// Both binaries present; only service unit missing.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "et version 6.4.9\n"}},
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "etserver version 6.4.9\n"}},
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.NotEmpty(t, actions)

	hasACL := false
	for _, a := range actions {
		if a.Description == "grant ACL tcp/2022 for eternal-terminal in Tailscale policy" {
			hasACL = true
		}
	}
	assert.True(t, hasACL, "ACL action must always be present")
}

func TestApply_Disabled_NoOp(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.EternalTerminal.Enabled = false
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner(), Platform: plat})
	require.NoError(t, m.Apply(context.Background()))
	assert.Empty(t, plat.installed)
	assert.Empty(t, plat.services)
}

func TestApply_InstallsViaPlatform(t *testing.T) {
	// et --version → not found (triggers install).
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}},
	)
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})
	err := m.Apply(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"eternal-terminal"}, plat.installed)
	require.Len(t, plat.services, 1)
	assert.Equal(t, "dev.abysslink.etserver", plat.services[0].Label)
	assert.True(t, plat.services[0].KeepAlive)
	assert.True(t, plat.services[0].RunAtLoad)
	// Service must run etserver on port 2022.
	assert.Contains(t, plat.services[0].Args, "etserver")
	assert.Contains(t, plat.services[0].Args, "2022")
}

func TestApply_AlreadyInstalled_SkipsInstall(t *testing.T) {
	// BOTH binaries present — no install needed.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "et version 6.4.9\n"}},       // et
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "etserver version 6.4.9\n"}}, // etserver
	)
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})
	err := m.Apply(context.Background())
	require.NoError(t, err)
	assert.Empty(t, plat.installed, "must not install when et AND etserver are already present")
	require.Len(t, plat.services, 1)
	assert.True(t, r.Done())
}

// TestApply_ServerMissing_StillInstalls is the W5b regression test: a present
// client (`et`) with a missing server (`etserver`) must still trigger the
// package install — the service Apply registers runs etserver.
func TestApply_ServerMissing_StillInstalls(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "et version 6.4.9\n"}},  // et present
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}}, // etserver missing
	)
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})
	require.NoError(t, m.Apply(context.Background()))
	assert.Equal(t, []string{"eternal-terminal"}, plat.installed,
		"missing etserver must trigger the package install even when et is present")
	require.Len(t, plat.services, 1)
	assert.True(t, r.Done())
}

// TestDetect_ServiceUnitPresent_NoWarning is the W5a regression test: Detect
// must look for the USER-level unit Apply actually writes (etServiceLabel via
// platform.ServiceInstall), not system unit paths Apply never touches. With
// the unit present, the et_service_unit_installed warning must not fire.
func TestDetect_ServiceUnitPresent_NoWarning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	unitPath, err := etServiceUnitPath(runtime.GOOS)
	require.NoError(t, err)
	if unitPath == "" {
		t.Skipf("unsupported GOOS %s", runtime.GOOS)
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(unitPath), 0o750))
	require.NoError(t, os.WriteFile(unitPath, []byte("unit"), 0o600))

	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "et version 6.4.9\n"}},
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "etserver version 6.4.9\n"}},
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	for _, f := range findings {
		assert.NotEqual(t, "et_service_unit_installed", f.Check,
			"unit written by Apply at %s must satisfy Detect", unitPath)
	}
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
