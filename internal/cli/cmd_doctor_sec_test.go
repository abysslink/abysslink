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

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSSHDConfig writes a minimal sshd_config fixture and returns its path.
func writeSSHDConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestParseSSHDConfigFile(t *testing.T) {
	t.Run("directive_present", func(t *testing.T) {
		p := writeSSHDConfig(t, "# comment\nPermitRootLogin yes\nX11Forwarding no\n")
		val, err := parseSSHDConfigFile(p, "permitrootlogin")
		require.NoError(t, err)
		assert.Equal(t, "yes", val)
	})
	t.Run("comment_skipped", func(t *testing.T) {
		p := writeSSHDConfig(t, "#PermitRootLogin yes\n")
		val, err := parseSSHDConfigFile(p, "permitrootlogin")
		require.NoError(t, err)
		assert.Equal(t, "", val) // commented → treated as absent
	})
	t.Run("absent_file", func(t *testing.T) {
		_, err := parseSSHDConfigFile(filepath.Join(t.TempDir(), "nope"), "permitrootlogin")
		assert.ErrorIs(t, err, errSSHDAbsent)
	})
}

func TestParseSSHDTOutput(t *testing.T) {
	out := "permitrootlogin prohibit-password\nx11forwarding no\nmaxauthtries 6\n"
	val, found := parseSSHDTOutput(out, "maxauthtries")
	assert.True(t, found)
	assert.Equal(t, "6", val)
	_, found = parseSSHDTOutput(out, "ciphers")
	assert.False(t, found)
}

func TestSecSSHPermitRoot(t *testing.T) {
	ctx := context.Background()
	t.Run("yes", func(t *testing.T) {
		p := writeSSHDConfig(t, "PermitRootLogin yes\n")
		f := secSSHPermitRootCheckPath(ctx, p)
		assert.Equal(t, "sec-ssh-permitroot", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("prohibit-password", func(t *testing.T) {
		p := writeSSHDConfig(t, "PermitRootLogin prohibit-password\n")
		f := secSSHPermitRootCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
	t.Run("absent_sshd", func(t *testing.T) {
		f := secSSHPermitRootCheckPath(ctx, filepath.Join(t.TempDir(), "missing"))
		assert.Equal(t, modules.SeverityOK, f.Severity)
		assert.Contains(t, f.Message, "sshd not installed")
	})
	t.Run("default_absent_directive", func(t *testing.T) {
		p := writeSSHDConfig(t, "X11Forwarding no\n") // no PermitRootLogin → default prohibit-password
		f := secSSHPermitRootCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecSSHX11Forwarding(t *testing.T) {
	ctx := context.Background()
	t.Run("yes", func(t *testing.T) {
		p := writeSSHDConfig(t, "X11Forwarding yes\n")
		f := secSSHX11ForwardingCheckPath(ctx, p)
		assert.Equal(t, "sec-ssh-x11forwarding", f.Check)
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	})
	t.Run("default_no", func(t *testing.T) {
		p := writeSSHDConfig(t, "PermitRootLogin no\n")
		f := secSSHX11ForwardingCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecSSHAgentForwarding(t *testing.T) {
	ctx := context.Background()
	t.Run("default_yes", func(t *testing.T) {
		p := writeSSHDConfig(t, "PermitRootLogin no\n") // absent → compiled-in default yes
		f := secSSHAgentForwardingCheckPath(ctx, p)
		assert.Equal(t, "sec-ssh-agentforwarding", f.Check)
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	})
	t.Run("explicit_no", func(t *testing.T) {
		p := writeSSHDConfig(t, "AllowAgentForwarding no\n")
		f := secSSHAgentForwardingCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecSSHMaxAuthTries(t *testing.T) {
	ctx := context.Background()
	t.Run("6", func(t *testing.T) {
		p := writeSSHDConfig(t, "MaxAuthTries 6\n")
		f := secSSHMaxAuthTriesCheckPath(ctx, p)
		assert.Equal(t, "sec-ssh-maxauthtries", f.Check)
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	})
	t.Run("4", func(t *testing.T) {
		p := writeSSHDConfig(t, "MaxAuthTries 4\n")
		f := secSSHMaxAuthTriesCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecSSHLoginGraceTime(t *testing.T) {
	ctx := context.Background()
	t.Run("120", func(t *testing.T) {
		p := writeSSHDConfig(t, "LoginGraceTime 120\n")
		f := secSSHLoginGraceTimeCheckPath(ctx, p)
		assert.Equal(t, "sec-ssh-logingracetime", f.Check)
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	})
	t.Run("60", func(t *testing.T) {
		p := writeSSHDConfig(t, "LoginGraceTime 60\n")
		f := secSSHLoginGraceTimeCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecSSHCiphers(t *testing.T) {
	ctx := context.Background()
	t.Run("bad", func(t *testing.T) {
		p := writeSSHDConfig(t, "Ciphers aes128-cbc,aes256-ctr\n")
		f := secSSHCiphersCheckPath(ctx, p)
		assert.Equal(t, "sec-ssh-ciphers", f.Check)
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	})
	t.Run("good", func(t *testing.T) {
		p := writeSSHDConfig(t, "Ciphers chacha20-poly1305@openssh.com,aes256-ctr\n")
		f := secSSHCiphersCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
	t.Run("absent_ok", func(t *testing.T) {
		p := writeSSHDConfig(t, "PermitRootLogin no\n")
		f := secSSHCiphersCheckPath(ctx, p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecAuditLogExists(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		f := secAuditLogExistsCheckPath(filepath.Join(t.TempDir(), "nope.log"))
		assert.Equal(t, "sec-audit-log-exists", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("present", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.log")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		f := secAuditLogExistsCheckPath(p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecAuditLogPerms(t *testing.T) {
	t.Run("0644", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.log")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(p, 0o644)) // bypass umask
		f := secAuditLogPermsCheckPath(p)
		assert.Equal(t, "sec-audit-log-perms", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("0600", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.log")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		f := secAuditLogPermsCheckPath(p)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecNoWorldReadableConfig(t *testing.T) {
	t.Run("world_writable", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "abysslink.yaml")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		// Chmod explicitly to bypass the process umask, which would otherwise
		// strip the group/other-write bits the check is looking for.
		require.NoError(t, os.Chmod(p, 0o646))
		f := secNoWorldReadableConfigCheckDir(dir)
		assert.Equal(t, "sec-no-world-readable-config", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("world_readable", func(t *testing.T) {
		// WR-03: a 0o644 config file is world-READABLE — exactly what the check
		// name and SEC-04 promise to catch. The pre-fix 0o022-only mask let this
		// pass clean (false-OK); the looseConfigBits (0o077) mask must FATAL it.
		dir := t.TempDir()
		p := filepath.Join(dir, "abysslink.yaml")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(p, 0o644)) // bypass umask
		f := secNoWorldReadableConfigCheckDir(dir)
		assert.Equal(t, "sec-no-world-readable-config", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("group_readable", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "abysslink.yaml")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(p, 0o640)) // group-read only; bypass umask
		f := secNoWorldReadableConfigCheckDir(dir)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("restricted", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "abysslink.yaml"), []byte("x"), 0o600))
		f := secNoWorldReadableConfigCheckDir(dir)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecDaemonSocketPerms(t *testing.T) {
	t.Run("bad", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "abysslinkd.sock")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(p, 0o644)) // bypass umask
		f := secDaemonSocketPermsCheckPath(p)
		assert.Equal(t, "sec-daemon-socket-perms", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("absent", func(t *testing.T) {
		f := secDaemonSocketPermsCheckPath(filepath.Join(t.TempDir(), "nope.sock"))
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

func TestSecListenerBind(t *testing.T) {
	t.Run("wildcard", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Observability.Metrics.BindAddr = "0.0.0.0:9090"
		f := secListenerBindCheck(cfg)
		assert.Equal(t, "sec-listener-bind", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("tailnet", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Observability.Metrics.BindAddr = "100.64.0.1:9090"
		cfg.WebUI.BindAddr = "100.64.0.1:8443"
		f := secListenerBindCheck(cfg)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
	t.Run("webui_wildcard", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.WebUI.BindAddr = "::"
		f := secListenerBindCheck(cfg)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
}

func TestSecFunnelSchema(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cfg := config.Defaults()
		f := secFunnelSchemaCheck(cfg)
		assert.Equal(t, "sec-funnel-schema", f.Check)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
}

// fakeDiskPlatform is a platform.Platform stub overriding only disk encryption.
type fakeDiskPlatform struct {
	platform.Platform
	state platform.DiskState
	err   error
}

func (f fakeDiskPlatform) DiskEncryptionStatus(_ context.Context) (platform.DiskState, error) {
	return f.state, f.err
}

func TestSecDiskEncryption(t *testing.T) {
	ctx := context.Background()
	t.Run("encrypted", func(t *testing.T) {
		f := secDiskEncryptionCheck(ctx, fakeDiskPlatform{state: platform.DiskEncrypted})
		assert.Equal(t, "sec-disk-encryption", f.Check)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
	t.Run("unencrypted", func(t *testing.T) {
		f := secDiskEncryptionCheck(ctx, fakeDiskPlatform{state: platform.DiskUnencrypted})
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("unknown", func(t *testing.T) {
		f := secDiskEncryptionCheck(ctx, fakeDiskPlatform{state: platform.DiskUnknown})
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	})
}

func TestSecAliasChecks(t *testing.T) {
	t.Run("metrics_bind", func(t *testing.T) {
		src := []modules.Finding{{Module: "metrics", Check: "metrics-bind-tailnet", Severity: modules.SeverityFatal, Message: "bad"}}
		f := secMetricsBindAlias(src)
		assert.Equal(t, "sec-metrics-bind", f.Check)
		assert.Equal(t, "sec", f.Module)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("metrics_bind_missing", func(t *testing.T) {
		f := secMetricsBindAlias(nil)
		assert.Equal(t, "sec-metrics-bind", f.Check)
		assert.Equal(t, modules.SeverityOK, f.Severity)
	})
	t.Run("webui_bind", func(t *testing.T) {
		src := []modules.Finding{{Module: "webui", Check: "webui-bind", Severity: modules.SeverityFatal, Message: "bad"}}
		f := secWebUIBindAlias(src)
		assert.Equal(t, "sec-webui-bind", f.Check)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
	})
	t.Run("audit_anchor_age", func(t *testing.T) {
		src := []modules.Finding{{Module: "audit", Check: "audit-anchor-age", Severity: modules.SeverityWarning, Message: "old"}}
		f := secAuditAnchorAgeAlias(src)
		assert.Equal(t, "sec-audit-anchor-age", f.Check)
		assert.Equal(t, modules.SeverityWarning, f.Severity)
	})
}

func TestSecBinarySignedAndUpgrade(t *testing.T) {
	ctx := context.Background()
	runner := shell.NewMockRunner()
	bf := secBinarySignedCheck(ctx, runner)
	assert.Equal(t, "sec-binary-signed", bf.Check)
	assert.Equal(t, "sec", bf.Module)
	uf := secUpgradeVerifiedCheck()
	assert.Equal(t, "sec-upgrade-verified", uf.Check)
	assert.Equal(t, "sec", uf.Module)
}

func TestSecDoctorFindings(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Observability.Metrics.BindAddr = "100.64.0.1:9090"
	cfg.WebUI.BindAddr = "100.64.0.1:8443"

	cc := &cmdContext{cfg: cfg, runner: shell.NewMockRunner()}
	deps := modules.Deps{Platform: fakeDiskPlatform{state: platform.DiskEncrypted}}

	metFindings := []modules.Finding{{Module: "metrics", Check: "metrics-bind-tailnet", Severity: modules.SeverityOK}}
	webuiFindings := []modules.Finding{{Module: "webui", Check: "webui-bind", Severity: modules.SeverityOK}}
	auditFindings := []modules.Finding{{Module: "audit", Check: "audit-anchor-age", Severity: modules.SeverityWarning}}

	findings := secDoctorFindings(ctx, cc, deps, false, metFindings, webuiFindings, auditFindings)

	require.Len(t, findings, 18, "secDoctorFindings must return exactly 18 findings")

	want := map[string]bool{
		"sec-ssh-permitroot": true, "sec-ssh-x11forwarding": true, "sec-ssh-agentforwarding": true,
		"sec-ssh-maxauthtries": true, "sec-ssh-logingracetime": true, "sec-ssh-ciphers": true,
		"sec-audit-log-exists": true, "sec-audit-log-perms": true, "sec-no-world-readable-config": true,
		"sec-daemon-socket-perms": true, "sec-listener-bind": true, "sec-funnel-schema": true,
		"sec-disk-encryption": true, "sec-binary-signed": true, "sec-upgrade-verified": true,
		"sec-metrics-bind": true, "sec-webui-bind": true, "sec-audit-anchor-age": true,
	}
	got := map[string]bool{}
	for _, f := range findings {
		assert.Equal(t, "sec", f.Module, "all sec findings carry Module=sec: %s", f.Check)
		got[f.Check] = true
	}
	for id := range want {
		assert.True(t, got[id], "missing check ID %q", id)
	}
}
