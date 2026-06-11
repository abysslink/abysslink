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

package codeserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// mockPlatform is a no-op platform implementation for unit tests.
type mockPlatform struct {
	installed []string
	services  []platform.ServiceSpec
}

func (p *mockPlatform) OS() string                              { return "linux" }
func (p *mockPlatform) Distro() platform.Distro                 { return platform.DistroUnknown }
func (p *mockPlatform) PackageManager() platform.PackageManager { return platform.PkgApt }
func (p *mockPlatform) InstallPackage(_ context.Context, name string) error {
	p.installed = append(p.installed, name)
	return nil
}
func (p *mockPlatform) RemovePackage(_ context.Context, _ string) error { return nil }
func (p *mockPlatform) ServiceInstall(_ context.Context, spec platform.ServiceSpec) error {
	p.services = append(p.services, spec)
	return nil
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

// stubKeychain is an in-memory keychain whose Get never fails.
type stubKeychain struct{ pw string }

func (s *stubKeychain) Set(_ context.Context, _, _, secret string) error {
	s.pw = secret
	return nil
}
func (s *stubKeychain) Get(_ context.Context, _, _ string) (string, error) { return s.pw, nil }
func (s *stubKeychain) Delete(_ context.Context, _, _ string) error        { return nil }

// errKeychain fails Get with a non-ErrNotFound error (keychain locked).
type errKeychain struct{}

func (errKeychain) Set(_ context.Context, _, _, _ string) error { return nil }
func (errKeychain) Get(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("keychain locked")
}
func (errKeychain) Delete(_ context.Context, _, _ string) error { return nil }

func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.CodeServer.Enabled = true
	return cfg
}

func TestIsBindAddrTailnetOnly(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		// Acceptable: specific tailnet IPs (v4 and v6) and MagicDNS names.
		{"100.64.1.2:8080", true},
		{"100.120.45.67:8080", true},
		{"[fd7a:115c:a1e0::1]:8080", true},
		{"mybox.tail1234.ts.net:8080", true},

		// Rejected: empty / wildcard hosts (NET-09 matrix).
		{"", false},
		{":8080", false},        // empty host — IPv4 all-interfaces
		{"0.0.0.0:8080", false}, // IPv4 wildcard with port
		{"0.0.0.0", false},      // IPv4 wildcard without port
		{"[::]:8080", false},    // IPv6 wildcard with port
		{"::", false},           // IPv6 wildcard without port
		{"[::]", false},         // bracketed IPv6 wildcard without port

		// Rejected: loopback hosts.
		{"127.0.0.1:8080", false},
		{"127.0.0.1", false},
		{"[::1]:8080", false},
		{"::1", false},
		{"localhost:8080", false},
		{"localhost", false},
		{"LOCALHOST:8080", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, isBindAddrTailnetOnly(tc.addr), "addr=%q", tc.addr)
	}
}

// TestEnsurePassword_KeychainUnavailableAborts mirrors ntfy's NET-12 floor: a
// transient/locked keychain error must abort — never silently generate a new
// password (it would desync the keychain from the hash in config.yaml).
func TestEnsurePassword_KeychainUnavailableAborts(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledCfg(), Keychain: errKeychain{}})
	_, err := m.ensurePassword(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keychain unavailable",
		"a non-NotFound keychain error must abort with a clear message")
}

// TestEnsurePassword_EmptyGenerates: a definitive miss (nil error, empty
// value) generates and stores a fresh password.
func TestEnsurePassword_EmptyGenerates(t *testing.T) {
	kc := &stubKeychain{}
	m := New(modules.Deps{Cfg: enabledCfg(), Keychain: kc})
	pw, err := m.ensurePassword(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, pw)
	assert.Equal(t, pw, kc.pw, "generated password must be stored in the keychain")
}

func TestArgon2idRoundTrip(t *testing.T) {
	phc, err := hashArgon2id("s3cret")
	require.NoError(t, err)
	assert.Contains(t, phc, "$argon2id$v=19$", "must emit a PHC-format argon2id string")
	assert.True(t, verifyArgon2id(phc, "s3cret"))
	assert.False(t, verifyArgon2id(phc, "wrong"))
	assert.False(t, verifyArgon2id("", "s3cret"))
	assert.False(t, verifyArgon2id("$argon2i$v=19$m=65536,t=1,p=4$AAAA$BBBB", "s3cret"),
		"non-argon2id variants must not verify")
}

// applyOnce runs Apply against a temp HOME with a scripted runner and returns
// the config path. Runner script: code-server --version (ok), tailscale ip.
func applyOnce(t *testing.T, kc *stubKeychain, plat *mockPlatform, auditLog string) string {
	t.Helper()
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "4.20.0\n"}},     // code-server --version
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "100.64.1.2\n"}}, // tailscale ip --4
	)
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r, Platform: plat, Keychain: kc, Audit: audit.New(auditLog)})
	require.NoError(t, m.Apply(context.Background()))
	require.True(t, r.Done())
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	return filepath.Join(home, codeServerConfigPath)
}

// TestApply_WritesHashedPasswordNotPlaintext: config.yaml must carry the
// argon2id hash, never the keychain plaintext.
func TestApply_WritesHashedPasswordNotPlaintext(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kc := &stubKeychain{pw: "super-secret-pw"}
	cfgPath := applyOnce(t, kc, &mockPlatform{}, filepath.Join(t.TempDir(), "audit.log"))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "hashed-password: $argon2id$")
	assert.NotContains(t, content, "super-secret-pw", "plaintext password must never be at rest in config.yaml")
	assert.NotContains(t, content, "\npassword:", "no plaintext password key")
	assert.Contains(t, content, "bind-addr: 100.64.1.2:8080")
}

// TestApply_SecondRunDoesNotRewriteConfig: a converged config must not be
// rewritten on every Apply (audit/backup churn) even though the argon2id salt
// would make a fresh marshal differ byte-wise.
func TestApply_SecondRunDoesNotRewriteConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kc := &stubKeychain{pw: "super-secret-pw"}
	auditLog := filepath.Join(t.TempDir(), "audit.log")

	cfgPath := applyOnce(t, kc, &mockPlatform{}, auditLog)
	first, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	entriesAfterFirst, err := audit.ReadLog(auditLog)
	require.NoError(t, err)

	_ = applyOnce(t, kc, &mockPlatform{}, auditLog)
	second, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	entriesAfterSecond, err := audit.ReadLog(auditLog)
	require.NoError(t, err)

	assert.Equal(t, first, second, "converged config must not be rewritten")
	assert.Equal(t, len(entriesAfterFirst), len(entriesAfterSecond),
		"no new audit entries on a converged second apply")
}

// TestApply_KeychainPasswordRotationRewrites: when the keychain password no
// longer matches the stored hash, Apply must rewrite the config.
func TestApply_KeychainPasswordRotationRewrites(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	auditLog := filepath.Join(t.TempDir(), "audit.log")

	cfgPath := applyOnce(t, &stubKeychain{pw: "old-pw"}, &mockPlatform{}, auditLog)
	first, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	_ = applyOnce(t, &stubKeychain{pw: "new-pw"}, &mockPlatform{}, auditLog)
	second, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "rotated keychain password must propagate to the hash")

	var cfg codeServerConfig
	// The file is YAML written by the module; parse and verify the new hash.
	require.NoError(t, yamlUnmarshal(second, &cfg))
	assert.True(t, verifyArgon2id(cfg.HashedPassword, "new-pw"))
}

// yamlUnmarshal is a tiny indirection so the test reads clearly.
func yamlUnmarshal(data []byte, v any) error { return yaml.Unmarshal(data, v) }
