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

package upsnap

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

// enabledCfg returns a config with the upsnap module enabled.
func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Upsnap.Enabled = true
	return cfg
}

// disabledCfg returns a config with the upsnap module disabled (default).
func disabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Upsnap.Enabled = false
	return cfg
}

// TestDetect_NotInstalled verifies that a missing upsnap binary produces an
// "installed" fatal finding.
func TestDetect_NotInstalled(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}},
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "installed", findings[0].Check)
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

// TestPlan_NotInstalled verifies that Plan produces an install action when
// upsnap is not on PATH.
func TestPlan_NotInstalled(t *testing.T) {
	// Plan calls Detect which runs "upsnap --version" and gets exit 127.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}},
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.NotEmpty(t, actions)

	var hasInstall bool
	for _, a := range actions {
		if a.Module == "upsnap" && strings.Contains(a.Description, "install") {
			hasInstall = true
		}
	}
	assert.True(t, hasInstall, "expected an install action referencing download URL")
}

// TestApply_NotOnPATH verifies that Apply returns an error containing the
// download URL when upsnap is not found.
func TestApply_NotOnPATH(t *testing.T) {
	r := shell.NewMockRunner(
		// upsnap --version: not found, no "upsnap" in combined output.
		shell.Call{Result: shell.Result{ExitCode: 127, Stdout: "", Stderr: "command not found"}},
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: &mockPlatform{}})
	err := m.Apply(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https://github.com/seriousm4x/UpSnap/releases",
		"error must contain the download URL")
}
