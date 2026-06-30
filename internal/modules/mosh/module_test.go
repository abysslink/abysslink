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

package mosh

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fake platforms -------------------------------------------------------
//
// The real darwin/linux platforms route their capability ops through
// shell.Runner; here we fake the Platform so the module's capability dispatch
// (PathLinker / AppFirewall / RangeFirewall) is exercised directly and the only
// shell.Runner calls left are the module's own: `mosh-server --version` and
// `brew --prefix`.

// basePlatform supplies no-op implementations of every platform.Platform method
// so the concrete fakes only declare what a test cares about.
type basePlatform struct{}

func (basePlatform) OS() string                              { return "fake" }
func (basePlatform) Distro() platform.Distro                 { return platform.DistroUnknown }
func (basePlatform) PackageManager() platform.PackageManager { return "" }
func (basePlatform) InstallPackage(context.Context, string) error {
	return nil
}
func (basePlatform) RemovePackage(context.Context, string) error { return nil }
func (basePlatform) ServiceInstall(context.Context, platform.ServiceSpec) error {
	return nil
}
func (basePlatform) ServiceUninstall(context.Context, string) error { return nil }
func (basePlatform) ServiceStart(context.Context, string) error     { return nil }
func (basePlatform) ServiceStop(context.Context, string) error      { return nil }
func (basePlatform) ServiceStatus(context.Context, string) (platform.ServiceStatus, error) {
	return platform.ServiceUnknown, nil
}
func (basePlatform) DiskEncryptionStatus(context.Context) (platform.DiskState, error) {
	return platform.DiskUnknown, nil
}
func (basePlatform) Firewall() platform.FirewallController { return &noopFirewall{} }
func (basePlatform) KeepAwake(context.Context, platform.KeepAwakeMode) error {
	return nil
}

type noopFirewall struct{}

func (*noopFirewall) AllowPort(context.Context, int, string) error { return nil }
func (*noopFirewall) DenyPort(context.Context, int, string) error  { return nil }
func (*noopFirewall) Status(context.Context) (string, error)       { return "disabled", nil }

// fakeDarwinPlatform implements platform.PathLinker; its firewall implements
// platform.AppFirewall — mirroring the real macOS platform's capability set.
type fakeDarwinPlatform struct {
	basePlatform
	fw           *fakeAppFirewall
	onSystemPath bool
	symlinkCalls int
	lastSymlink  string
}

func (f *fakeDarwinPlatform) Firewall() platform.FirewallController { return f.fw }
func (f *fakeDarwinPlatform) IsOnSystemPath(context.Context, string) (bool, error) {
	return f.onSystemPath, nil
}
func (f *fakeDarwinPlatform) SymlinkIntoSystemPath(_ context.Context, p string) error {
	f.symlinkCalls++
	f.lastSymlink = p
	return nil
}

type fakeAppFirewall struct {
	status        string
	allowed       bool
	allowAppCalls int
	lastAllowApp  string
}

func (f *fakeAppFirewall) AllowPort(context.Context, int, string) error { return nil }
func (f *fakeAppFirewall) DenyPort(context.Context, int, string) error  { return nil }
func (f *fakeAppFirewall) Status(context.Context) (string, error)       { return f.status, nil }
func (f *fakeAppFirewall) AllowApp(_ context.Context, p string) error {
	f.allowAppCalls++
	f.lastAllowApp = p
	return nil
}
func (f *fakeAppFirewall) IsAppAllowed(context.Context, string) (bool, error) {
	return f.allowed, nil
}

// fakeLinuxPlatform does NOT implement PathLinker/AppFirewall; its firewall
// implements platform.RangeFirewall — mirroring the real Linux platform.
type fakeLinuxPlatform struct {
	basePlatform
	fw *fakeRangeFirewall
}

func (f *fakeLinuxPlatform) Firewall() platform.FirewallController { return f.fw }

type fakeRangeFirewall struct {
	status          string
	allowed         bool
	allowRangeCalls int
	lastLo, lastHi  int
	lastProto       string
}

func (f *fakeRangeFirewall) AllowPort(context.Context, int, string) error { return nil }
func (f *fakeRangeFirewall) DenyPort(context.Context, int, string) error  { return nil }
func (f *fakeRangeFirewall) Status(context.Context) (string, error)       { return f.status, nil }
func (f *fakeRangeFirewall) AllowPortRange(_ context.Context, lo, hi int, proto string) error {
	f.allowRangeCalls++
	f.lastLo, f.lastHi, f.lastProto = lo, hi, proto
	return nil
}
func (f *fakeRangeFirewall) IsPortRangeAllowed(context.Context, int, int, string) (bool, error) {
	return f.allowed, nil
}

func enabledCfg() *config.Config {
	c := config.Defaults()
	c.Modules.Mosh.Enabled = true
	return c
}

func TestDetect_MoshNotInstalled_Warning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}})
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "installed", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_MoshInstalled_NoFindings(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "mosh-server (mosh 1.4.0)\n"}})
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDetect_MoshVersionInStderr_NoFindings(t *testing.T) {
	// Some versions of mosh-server print version to stderr and exit non-zero.
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "mosh 1.3.2 [build mosh 1.3.2]"}})
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "stderr contains 'mosh', should not flag as missing")
}

// installedCall scripts a successful `mosh-server --version`.
func installedCall() shell.Call {
	return shell.Call{Result: shell.Result{Stdout: "mosh-server (mosh 1.4.0)\n"}}
}

// brewPrefixCall scripts `brew --prefix` returning /opt/homebrew.
func brewPrefixCall() shell.Call {
	return shell.Call{Result: shell.Result{Stdout: "/opt/homebrew\n"}}
}

func TestPlan_Installed_WithGaps_EmitsReachabilityAction(t *testing.T) {
	// The regression: an already-installed-but-unreachable mosh must still
	// produce an action, else the runner skips Apply and never fixes it.
	r := shell.NewMockRunner(installedCall(), brewPrefixCall())
	plat := &fakeDarwinPlatform{fw: &fakeAppFirewall{status: "enabled", allowed: false}, onSystemPath: false}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, actions, 1, "installed-but-unreachable must plan an action")
	assert.Equal(t, "mosh", actions[0].Module)
}

func TestPlan_Installed_NoGaps_NoAction(t *testing.T) {
	r := shell.NewMockRunner(installedCall(), brewPrefixCall())
	plat := &fakeDarwinPlatform{fw: &fakeAppFirewall{status: "enabled", allowed: true}, onSystemPath: true}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, actions, "fully reachable mosh plans nothing (converged)")
}

func TestPlan_NotInstalled_EmitsInstallAction(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}})
	plat := &fakeDarwinPlatform{fw: &fakeAppFirewall{status: "enabled"}}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Description, "install mosh")
	assert.True(t, r.Done(), "not-installed path must not probe reachability")
}

func TestPlan_Disabled_NoAction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Mosh.Enabled = false
	r := shell.NewMockRunner() // any runner call would error
	m := New(modules.Deps{Cfg: cfg, Runner: r, Platform: &fakeDarwinPlatform{fw: &fakeAppFirewall{}}})

	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, actions)
	assert.True(t, r.Done(), "disabled module must not probe")
}

func TestApply_Darwin_LinksAndAllowsWhenMissing(t *testing.T) {
	r := shell.NewMockRunner(installedCall(), brewPrefixCall())
	fw := &fakeAppFirewall{status: "enabled", allowed: false}
	plat := &fakeDarwinPlatform{fw: fw, onSystemPath: false}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	require.NoError(t, m.Apply(context.Background()))

	assert.Equal(t, 1, plat.symlinkCalls, "symlink mosh-server onto PATH")
	assert.Equal(t, "/opt/homebrew/bin/mosh-server", plat.lastSymlink)
	assert.Equal(t, 1, fw.allowAppCalls, "allow mosh-server through app firewall")
	assert.Equal(t, "/opt/homebrew/bin/mosh-server", fw.lastAllowApp)
	assert.True(t, r.Done(), "exactly the scripted runner calls were made")
}

func TestApply_Darwin_Idempotent(t *testing.T) {
	r := shell.NewMockRunner(installedCall(), brewPrefixCall())
	fw := &fakeAppFirewall{status: "enabled", allowed: true}
	plat := &fakeDarwinPlatform{fw: fw, onSystemPath: true}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	require.NoError(t, m.Apply(context.Background()))

	assert.Zero(t, plat.symlinkCalls, "already on PATH → no symlink")
	assert.Zero(t, fw.allowAppCalls, "already allowed → no firewall write")
}

func TestApply_Linux_OpensRangeWhenFirewallActive(t *testing.T) {
	r := shell.NewMockRunner(installedCall()) // no brew --prefix on linux path
	fw := &fakeRangeFirewall{status: "enabled", allowed: false}
	plat := &fakeLinuxPlatform{fw: fw}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	require.NoError(t, m.Apply(context.Background()))

	assert.Equal(t, 1, fw.allowRangeCalls)
	assert.Equal(t, 60000, fw.lastLo)
	assert.Equal(t, 61000, fw.lastHi)
	assert.Equal(t, "udp", fw.lastProto)
	assert.True(t, r.Done())
}

func TestApply_Linux_FirewallInactive_SkipsRange(t *testing.T) {
	r := shell.NewMockRunner(installedCall())
	fw := &fakeRangeFirewall{status: "disabled"}
	plat := &fakeLinuxPlatform{fw: fw}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	require.NoError(t, m.Apply(context.Background()))
	assert.Zero(t, fw.allowRangeCalls, "no active firewall → nothing to open")
}

func TestVerify_Darwin_EmitsReachabilityFindings(t *testing.T) {
	r := shell.NewMockRunner(installedCall(), brewPrefixCall())
	fw := &fakeAppFirewall{status: "enabled", allowed: false}
	plat := &fakeDarwinPlatform{fw: fw, onSystemPath: false}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	findings, err := m.Verify(context.Background())
	require.NoError(t, err)

	checks := map[string]bool{}
	for _, f := range findings {
		checks[f.Check] = true
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	}
	assert.True(t, checks["mosh_path"], "expected mosh_path finding")
	assert.True(t, checks["mosh_firewall"], "expected mosh_firewall finding")
}

func TestVerify_Darwin_AllGood_NoFindings(t *testing.T) {
	r := shell.NewMockRunner(installedCall(), brewPrefixCall())
	fw := &fakeAppFirewall{status: "enabled", allowed: true}
	plat := &fakeDarwinPlatform{fw: fw, onSystemPath: true}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	findings, err := m.Verify(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestVerify_NotInstalled_NoFindings(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}})
	plat := &fakeDarwinPlatform{fw: &fakeAppFirewall{status: "enabled"}}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat})

	findings, err := m.Verify(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "not installed → Detect covers it, Verify stays quiet")
}

func TestVerify_Disabled_NoProbe(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Mosh.Enabled = false
	r := shell.NewMockRunner() // any runner call would error
	plat := &fakeDarwinPlatform{fw: &fakeAppFirewall{status: "enabled"}}
	m := New(modules.Deps{Cfg: cfg, Runner: r, Platform: plat})

	findings, err := m.Verify(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done(), "disabled module must not probe")
}
