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

package conformance_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/conformance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckNoSecretsInAuditLog_NoFile(t *testing.T) {
	ctx := context.Background()
	err := conformance.CheckNoSecretsInAuditLog(ctx, "/tmp/nonexistent-audit-log-xyzzy.log")
	assert.NoError(t, err, "missing audit log should not be an error")
}

func TestCheckNoSecretsInAuditLog_Clean(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Write a clean audit log (no secrets).
	clean := `{"time":"2026-01-01T00:00:00Z","op":"write","target":"/etc/foo","hash":"abcdef1234567890","dry_run":false}` + "\n"
	require.NoError(t, os.WriteFile(logPath, []byte(clean), 0o600))

	err := conformance.CheckNoSecretsInAuditLog(ctx, logPath)
	assert.NoError(t, err, "clean audit log should pass")
}

func TestCheckNoSecretsInAuditLog_SecretLeak(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Simulate a log entry that accidentally contains a token.
	leaky := `{"time":"2026-01-01T00:00:00Z","op":"write","target":"/etc/foo","token":"sk-ant-api03-AAABBBCCC111222333444555666777888"}` + "\n"
	require.NoError(t, os.WriteFile(logPath, []byte(leaky), 0o600))

	err := conformance.CheckNoSecretsInAuditLog(ctx, logPath)
	assert.Error(t, err, "audit log with leaked token should fail")
}

// TestCheckNoSecretsInAuditLog_BareTokens asserts that bare provider-prefixed
// token values leak-check positive even with no key= / key: shape around
// them. Tokens are assembled at runtime so no literal token sits in source.
func TestCheckNoSecretsInAuditLog_BareTokens(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		token string
	}{
		{"tailscale auth key", "tskey-auth-" + "kFGiAS1CNTRL-Xq8r2vZx9w"},
		{"github classic token", "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"},
		{"github fine-grained token", "github_pat_" + "9zY8xW7vU6tS5rQ4pO3nM2lK1jI0h"},
		{"aws access key id", "AKIA" + "IOSFODNN" + "7EXAMPLE"},
		{"slack token", "xoxb-" + "123456789012-abcdefghijklmnop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit.log")
			line := `{"time":"2026-01-01T00:00:00Z","op":"write","note":"` + tc.token + `"}` + "\n"
			require.NoError(t, os.WriteFile(logPath, []byte(line), 0o600))

			err := conformance.CheckNoSecretsInAuditLog(ctx, logPath)
			assert.Error(t, err, "bare token must be flagged as a leak")
		})
	}
}

// TestCheckNoSecretsInAuditLog_BareTokenFalsePositives guards the bare-token
// patterns against over-matching: ULIDs, content hashes, and ordinary
// hostnames must not trip the leak check.
func TestCheckNoSecretsInAuditLog_BareTokenFalsePositives(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	clean := `{"msg_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","hash":"deadbeefcafe0123456789abcdef0123456789abcdef0123456789abcdef0123","host":"rig-1"}` + "\n" +
		`{"note":"tmux task ghosted, see pane %3"}` + "\n"
	require.NoError(t, os.WriteFile(logPath, []byte(clean), 0o600))

	err := conformance.CheckNoSecretsInAuditLog(ctx, logPath)
	assert.NoError(t, err, "non-secret identifiers must not trip the bare-token patterns")
}

func TestCheckBinarySize_UnderLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fakebinary")
	// Write 1 byte — well under any limit.
	require.NoError(t, os.WriteFile(bin, []byte("x"), 0o600))

	err := conformance.CheckBinarySize(ctx, bin, 50<<20) // 50 MB
	assert.NoError(t, err)
}

func TestCheckBinarySize_OverLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fatbinary")
	// Write 2 bytes; set limit to 1 byte to force failure.
	require.NoError(t, os.WriteFile(bin, []byte("xx"), 0o600))

	err := conformance.CheckBinarySize(ctx, bin, 1)
	assert.Error(t, err)
}

func TestCheckBinarySize_Missing(t *testing.T) {
	ctx := context.Background()
	err := conformance.CheckBinarySize(ctx, "/tmp/no-such-binary-xyzzy", 50<<20)
	assert.Error(t, err)
}

func TestCheckNoTelemetry_CleanRepo(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	clean := `package foo

import "fmt"

func Hello() { fmt.Println("hi") }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "foo.go"), []byte(clean), 0o600))

	err := conformance.CheckNoTelemetry(ctx, dir)
	assert.NoError(t, err)
}

func TestCheckNoTelemetry_DetectsSentry(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	leaky := `package foo

import (
	"github.com/getsentry/sentry-go"
)

func track() { sentry.CaptureException(nil) }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.go"), []byte(leaky), 0o600))

	err := conformance.CheckNoTelemetry(ctx, dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "getsentry")
}

func TestCheckNtfyConfigBindAddr_RejectsWildcard(t *testing.T) {
	ctx := context.Background()

	err := conformance.CheckNtfyConfigBindAddr(ctx, `listen-http: "0.0.0.0:8080"`)
	assert.Error(t, err, "0.0.0.0 must be rejected")

	err = conformance.CheckNtfyConfigBindAddr(ctx, `listen-http: ":8080"`)
	assert.Error(t, err, "bare :port must be rejected")
}

func TestCheckNtfyConfigBindAddr_AcceptsTailnetIP(t *testing.T) {
	ctx := context.Background()
	cfg := `# ntfy config
listen-http: "100.64.1.2:8080"
auth-default-access: "deny-all"
`
	err := conformance.CheckNtfyConfigBindAddr(ctx, cfg)
	assert.NoError(t, err, "tailnet IP bind must be accepted")
}

func TestCheckNtfyConfigBindAddr_NoListenLine(t *testing.T) {
	ctx := context.Background()
	err := conformance.CheckNtfyConfigBindAddr(ctx, "auth-default-access: \"deny-all\"\n")
	assert.NoError(t, err, "no listen-http line should pass")
}

func TestCheckSSHHardeningDirectives_AllPresent(t *testing.T) {
	ctx := context.Background()
	cfg := `PasswordAuthentication no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitRootLogin no
AllowUsers alice
`
	err := conformance.CheckSSHHardeningDirectives(ctx, cfg)
	assert.NoError(t, err)
}

func TestCheckSSHHardeningDirectives_MissingDirective(t *testing.T) {
	ctx := context.Background()
	// Missing AllowAgentForwarding — threat-model violation.
	cfg := `PasswordAuthentication no
AllowTcpForwarding no
X11Forwarding no
PermitRootLogin no
`
	err := conformance.CheckSSHHardeningDirectives(ctx, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AllowAgentForwarding no")
}

// threatModelDefaults is a test adapter for CheckDefaultsMatchThreatModel.
type threatModelDefaults struct {
	lockEnabled      bool
	sshCheckPeriod   string
	disableMacOSSSHD bool
	firewallStealth  bool
	fileVaultPolicy  string
}

func (d threatModelDefaults) GetTailnetLockEnabled() bool { return d.lockEnabled }
func (d threatModelDefaults) GetSSHCheckPeriod() string   { return d.sshCheckPeriod }
func (d threatModelDefaults) GetDisableMacOSSSHD() bool   { return d.disableMacOSSSHD }
func (d threatModelDefaults) GetFirewallStealth() bool    { return d.firewallStealth }
func (d threatModelDefaults) GetFileVaultPolicy() string  { return d.fileVaultPolicy }

var allSecureDefaults = threatModelDefaults{
	lockEnabled:      true,
	sshCheckPeriod:   "12h",
	disableMacOSSSHD: true,
	firewallStealth:  true,
	fileVaultPolicy:  "required",
}

func TestCheckDefaultsMatchThreatModel_ValidDefaults(t *testing.T) {
	err := conformance.CheckDefaultsMatchThreatModel(context.Background(), allSecureDefaults)
	assert.NoError(t, err)
}

func TestCheckDefaultsMatchThreatModel_LockDisabled(t *testing.T) {
	d := allSecureDefaults
	d.lockEnabled = false
	err := conformance.CheckDefaultsMatchThreatModel(context.Background(), d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lock.enabled")
}

func TestCheckDefaultsMatchThreatModel_WrongCheckPeriod(t *testing.T) {
	d := allSecureDefaults
	d.sshCheckPeriod = "24h"
	err := conformance.CheckDefaultsMatchThreatModel(context.Background(), d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh_check_period")
}

func TestCheckDefaultsMatchThreatModel_DisableMacOSSSHDFalse(t *testing.T) {
	d := allSecureDefaults
	d.disableMacOSSSHD = false
	err := conformance.CheckDefaultsMatchThreatModel(context.Background(), d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disable_macos_sshd")
}

func TestCheckDefaultsMatchThreatModel_FirewallStealthFalse(t *testing.T) {
	d := allSecureDefaults
	d.firewallStealth = false
	err := conformance.CheckDefaultsMatchThreatModel(context.Background(), d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "firewall_stealth")
}

func TestCheckDefaultsMatchThreatModel_BadFileVaultPolicy(t *testing.T) {
	d := allSecureDefaults
	d.fileVaultPolicy = "optional"
	err := conformance.CheckDefaultsMatchThreatModel(context.Background(), d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "filevault")
}

func TestCheckDefaultsMatchThreatModel_MultipleFailures(t *testing.T) {
	d := threatModelDefaults{
		lockEnabled:      false,
		sshCheckPeriod:   "48h",
		disableMacOSSSHD: false,
		firewallStealth:  false,
		fileVaultPolicy:  "optional",
	}
	err := conformance.CheckDefaultsMatchThreatModel(context.Background(), d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lock.enabled")
	assert.Contains(t, err.Error(), "ssh_check_period")
	assert.Contains(t, err.Error(), "disable_macos_sshd")
	assert.Contains(t, err.Error(), "firewall_stealth")
	assert.Contains(t, err.Error(), "filevault")
}
