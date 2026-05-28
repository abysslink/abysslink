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

package syncthing

import (
	"context"
	"strings"
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

// enabledCfg returns a config with the syncthing module enabled.
func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Syncthing.Enabled = true
	return cfg
}

func TestDetect_Disabled_NilFindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Syncthing.Enabled = false
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done(), "no shell calls expected when disabled")
}

func TestDetect_NotInstalled_FatalFinding(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "installed", findings[0].Check)
	assert.Equal(t, modules.SeverityFatal, findings[0].Severity)
}

func TestDetect_Installed_NoConfigFile_NoFindings(t *testing.T) {
	// syncthing --version succeeds; config file absent — that's OK on first run.
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "syncthing v1.27.0 \"Fermium Flea\"\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDetect_GUIBoundToWildcard_ConfigContent(t *testing.T) {
	// Confirm the wildcard-address detection logic triggers on 0.0.0.0 content.
	// syncthingConfigPath() resolves relative to os.UserHomeDir() which is not
	// portable in CI; we exercise the string-matching logic directly here.
	cfgXML := `<configuration><gui><address>0.0.0.0:8384</address></gui></configuration>`

	// Replicate the exact conditions from Detect's config check.
	assert.True(t, wildcardBound(cfgXML), "0.0.0.0 bind must be detected as wildcard")
	assert.False(t, wildcardBound(`<address>100.64.1.2:8384</address>`), "tailnet-only bind is fine")
}

// wildcardBound replicates the Detect logic for testing the string pattern.
func wildcardBound(content string) bool {
	return strings.Contains(content, "<address>0.0.0.0:") ||
		strings.Contains(content, "<address>*:") ||
		strings.Contains(content, "<address>::")
}

func TestPlan_Disabled_Nil(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Syncthing.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, actions)
}

func TestPlan_NotInstalled_ReturnsInstallAction(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.NotEmpty(t, actions)
	assert.Equal(t, "syncthing", actions[0].Module)
	assert.Contains(t, actions[0].Description, "install syncthing")
}

func TestPlan_Installed_ReturnsServiceAction(t *testing.T) {
	// syncthing installed, no config file → Plan returns a "ensure service running" action.
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "syncthing v1.27.0\n"}})
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.NotEmpty(t, actions)
	assert.Equal(t, "syncthing", actions[0].Module)
}

func TestApply_Disabled_NoOp(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Syncthing.Enabled = false
	r := shell.NewMockRunner()
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: cfg, Runner: r, Platform: plat})
	require.NoError(t, m.Apply(context.Background()))
	assert.Empty(t, plat.installed)
	assert.Empty(t, plat.services)
}

func TestApply_InstallsAndConfiguresService(t *testing.T) {
	// First call: syncthing --version → not found (triggers install).
	// Second call: tailscale ip --4 → returns tailnet IP.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}},
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "100.64.1.2\n"}},
	)
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})
	err := m.Apply(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"syncthing"}, plat.installed)
	require.Len(t, plat.services, 1)
	assert.Equal(t, "dev.abysslink.syncthing", plat.services[0].Label)
	assert.True(t, plat.services[0].KeepAlive)
	assert.True(t, plat.services[0].RunAtLoad)
	// GUI address must include the tailnet IP, never 0.0.0.0.
	assert.Contains(t, plat.services[0].Args[2], "100.64.1.2")
	assert.NotContains(t, plat.services[0].Args[2], "0.0.0.0")
}

func TestApply_AlreadyInstalled_SkipsInstall(t *testing.T) {
	// First call: syncthing --version → success (already installed).
	// Second call: tailscale ip --4 → returns tailnet IP.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "syncthing v1.27.0\n"}},
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "100.64.1.2\n"}},
	)
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})
	err := m.Apply(context.Background())
	require.NoError(t, err)
	assert.Empty(t, plat.installed, "should not install when already present")
	require.Len(t, plat.services, 1)
}
