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

package ttyd

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

// mockPlatform is a no-op platform for tests.
type mockPlatform struct {
	serviceInstallErr error
	installedSpec     platform.ServiceSpec
}

func (p *mockPlatform) OS() string                                       { return "test" }
func (p *mockPlatform) Distro() platform.Distro                          { return platform.DistroUnknown }
func (p *mockPlatform) PackageManager() platform.PackageManager          { return "" }
func (p *mockPlatform) InstallPackage(_ context.Context, _ string) error { return nil }
func (p *mockPlatform) RemovePackage(_ context.Context, _ string) error  { return nil }
func (p *mockPlatform) ServiceInstall(_ context.Context, spec platform.ServiceSpec) error {
	p.installedSpec = spec
	return p.serviceInstallErr
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

// enabledCfg returns a config with the ttyd module enabled.
func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Ttyd.Enabled = true
	return cfg
}

// disabledCfg returns a config with the ttyd module disabled (default).
func disabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Ttyd.Enabled = false
	return cfg
}

// TestDetect_NotInstalled verifies that a missing ttyd binary produces a
// "ttyd_installed" fatal finding.
func TestDetect_NotInstalled(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}},
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "ttyd_installed", findings[0].Check)
	assert.Equal(t, modules.SeverityFatal, findings[0].Severity)
}

// TestDetect_Disabled verifies that a disabled module returns no findings.
func TestDetect_Disabled(t *testing.T) {
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: disabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done(), "no runner calls expected when disabled")
}

// TestPlan_Disabled verifies that Plan returns nil when the module is disabled.
func TestPlan_Disabled(t *testing.T) {
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: disabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, actions)
}

// TestPlan_NotInstalled verifies that Plan produces actions (including warning)
// when ttyd is not installed.
func TestPlan_NotInstalled(t *testing.T) {
	// Plan calls Detect, which runs "ttyd --version" and gets exit 127.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}},
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.NotEmpty(t, actions)

	// Expect an install action.
	var found bool
	for _, a := range actions {
		if a.Module == "ttyd" && !a.Reversible {
			found = true
		}
	}
	assert.True(t, found, "expected a non-reversible install action")

	// Expect the security warning action.
	var hasWarning bool
	for _, a := range actions {
		if a.Module == "ttyd" && strings.Contains(a.Description, "WARNING") {
			hasWarning = true
		}
	}
	assert.True(t, hasWarning, "expected a WARNING action")
}

// TestApply_BindsTailnetIP verifies that Apply installs the service bound to
// the tailscale IP returned by "tailscale ip --4".
func TestApply_BindsTailnetIP(t *testing.T) {
	const tailnetIP = "100.64.1.99"
	r := shell.NewMockRunner(
		// ttyd --version check (already installed)
		shell.Call{Result: shell.Result{Stdout: "ttyd version 1.7.7\n"}},
		// tailscale ip --4
		shell.Call{Result: shell.Result{Stdout: tailnetIP + "\n"}},
	)
	plat := &mockPlatform{}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})
	err := m.Apply(context.Background())
	require.NoError(t, err)
	assert.True(t, r.Done(), "all scripted runner calls must be consumed")

	// Verify the service is bound to the tailnet IP.
	spec := plat.installedSpec
	assert.Equal(t, "dev.abysslink.ttyd", spec.Label)
	require.NotEmpty(t, spec.Args)
	assert.Equal(t, "ttyd", spec.Args[0])

	var hasIP bool
	for _, arg := range spec.Args {
		if arg == tailnetIP {
			hasIP = true
		}
	}
	assert.True(t, hasIP, "service args must include the tailnet IP %q", tailnetIP)
}
