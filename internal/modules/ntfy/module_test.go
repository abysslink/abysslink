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

package ntfy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPlatform is a minimal platform.Platform for unit tests.
type testPlatform struct{}

func (p *testPlatform) OS() string                              { return "linux" }
func (p *testPlatform) Distro() platform.Distro                 { return platform.DistroUnknown }
func (p *testPlatform) PackageManager() platform.PackageManager { return platform.PkgApt }
func (p *testPlatform) InstallPackage(_ context.Context, _ string) error {
	return nil
}
func (p *testPlatform) RemovePackage(_ context.Context, _ string) error { return nil }
func (p *testPlatform) ServiceInstall(_ context.Context, _ platform.ServiceSpec) error {
	return nil
}
func (p *testPlatform) ServiceUninstall(_ context.Context, _ string) error { return nil }
func (p *testPlatform) ServiceStart(_ context.Context, _ string) error     { return nil }
func (p *testPlatform) ServiceStop(_ context.Context, _ string) error      { return nil }
func (p *testPlatform) ServiceStatus(_ context.Context, _ string) (platform.ServiceStatus, error) {
	return platform.ServiceUnknown, nil
}
func (p *testPlatform) DiskEncryptionStatus(_ context.Context) (platform.DiskState, error) {
	return platform.DiskUnknown, nil
}
func (p *testPlatform) Firewall() platform.FirewallController                       { return nil }
func (p *testPlatform) KeepAwake(_ context.Context, _ platform.KeepAwakeMode) error { return nil }

func TestGenerateServerConfig_BindsTailnetIPNotWildcard(t *testing.T) {
	m := New(modules.Deps{Cfg: config.Defaults()})
	out := string(m.generateServerConfig("100.64.1.2", "/home/testuser"))

	assert.Contains(t, out, "listen-http: \"100.64.1.2:2586\"", "must bind to the tailnet IP")
	assert.NotContains(t, out, "0.0.0.0", "must never bind to all interfaces")
	assert.Contains(t, out, "auth-default-access: \"deny-all\"")
}

func TestHasWildcardListen(t *testing.T) {
	assert.True(t, hasWildcardListen(`listen-http: ":2586"`), "bare :port binds to all interfaces")
	assert.False(t, hasWildcardListen(`listen-http: "100.64.1.2:2586"`))
	assert.False(t, hasWildcardListen("no listen line here"))
}

func TestGenerateServerConfig_IsYAMLish(t *testing.T) {
	m := New(modules.Deps{Cfg: config.Defaults()})
	out := string(m.generateServerConfig("100.64.1.2", "/home/testuser"))
	assert.True(t, strings.HasPrefix(out, "# ntfy server config"))
}

func TestListenAddressOK(t *testing.T) {
	// Clean path: config file exists and binds to tailnet IP (not 0.0.0.0) →
	// expect SeverityOK finding with Check=="listen_address".
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Write a valid ntfy server.yml that binds to a tailnet IP, not 0.0.0.0.
	cfgDir := filepath.Join(dir, ".config", "ntfy")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgContent := `listen-http: "100.64.1.2:2586"` + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "server.yml"), []byte(cfgContent), 0o600))

	// Mock runner: ntfyBinaryPresent returns true (binary present, has "serve" command).
	// ntfyDockerRunning → false (docker inspect fails).
	r := shell.NewMockRunner(
		// ntfyBinaryPresent: ntfy --help → includes "serve"
		shell.Call{Result: shell.Result{Stdout: "serve  Start ntfy server\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}})

	findings, err := m.Detect(context.Background())
	require.NoError(t, err)

	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "listen_address" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"listen_address\" on clean path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "tailnet-bound listen_address must emit SeverityOK")
}
