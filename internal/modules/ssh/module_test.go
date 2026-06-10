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

package ssh

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHardenedSSHDConfig(t *testing.T) {
	cfg := hardenedSSHDConfig("alice")

	// Security-critical directives must be present.
	assert.Contains(t, cfg, "PasswordAuthentication no")
	assert.Contains(t, cfg, "AllowAgentForwarding no", "prevent a compromised phone pivoting via a forwarded agent")
	assert.Contains(t, cfg, "AllowTcpForwarding no")
	assert.Contains(t, cfg, "X11Forwarding no")
	assert.Contains(t, cfg, "PermitRootLogin no")
	assert.Contains(t, cfg, "AllowUsers alice")
}

// TestRemoteLoginOK asserts that detectDarwin emits SeverityOK(Check=="remote_login")
// when Remote Login is correctly OFF while mode=tailscale.
func TestRemoteLoginOK(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"

	// systemsetup reports "Remote Login: Off"
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "Remote Login: Off\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings := m.detectDarwin(context.Background())

	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "remote_login" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"remote_login\" on clean path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "sshd correctly off: must emit SeverityOK for remote_login")
}

// TestSshdRunningOK asserts that detectLinux emits SeverityOK(Check=="sshd_running")
// when the sshd service is correctly inactive while mode=tailscale.
func TestSshdRunningOK(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"

	// systemctl is-active sshd → "inactive", then the NET-08 fallback probes
	// ssh.service (also inactive) before trusting the "off" verdict.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 3}},
	)
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings := m.detectLinux(context.Background())

	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "sshd_running" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"sshd_running\" on clean path, got none")
	}
	require.Equal(t, modules.SeverityOK, found.Severity, "sshd correctly off: must emit SeverityOK for sshd_running")
}

// TestSshdRunningFallbackSSHUnit is the NET-08 regression test: on distros
// that ship only ssh.service (Debian/Ubuntu), `systemctl is-active sshd`
// returns a non-zero exit with "inactive"/"unknown" on stdout but WITHOUT an
// exec error. detectLinux must still probe the ssh unit and flag the running
// daemon — never report a false "OpenSSH daemon correctly off".
func TestSshdRunningFallbackSSHUnit(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"

	r := shell.NewMockRunner(
		// systemctl is-active sshd → "inactive", exit 3, NO exec error.
		shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 3}},
		// fallback: systemctl is-active ssh → "active" (the daemon IS running).
		shell.Call{Result: shell.Result{Stdout: "active\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings := m.detectLinux(context.Background())
	require.True(t, r.Done(), "detectLinux must probe both sshd and ssh units")

	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "sshd_running" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "expected a sshd_running finding when ssh.service is active")
	assert.Equal(t, modules.SeverityWarning, found.Severity,
		"a running ssh.service must be flagged, not reported as correctly off (NET-08)")
}

// TestSshdRunningFallbackBothInactive asserts the clean path on ssh.service-only
// distros: both probes report inactive → SeverityOK.
func TestSshdRunningFallbackBothInactive(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"

	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "unknown\n", ExitCode: 4}},
		shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 3}},
	)
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings := m.detectLinux(context.Background())
	require.True(t, r.Done())

	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "sshd_running" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityOK, found.Severity, "both units inactive → OK")
}

// TestApply_SeverityOK_NoMutation asserts that Apply runs NO privileged mutation
// when all Detect findings are SeverityOK (sshd already correctly off).
// This is the CR-02 regression test.
//
// The MockRunner is scripted with exactly one call (the Detect probe). If Apply
// tried to issue a second runner call (the "disable" mutation), MockRunner.Run
// would return an error for the unexpected call — causing Apply to fail and the
// test to detect the regression.
func TestApply_SeverityOK_NoMutation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"
	cfg.Modules.SSH.Enabled = true

	switch runtime.GOOS {
	case "darwin":
		// Detect calls systemsetup -getremotelogin → "Remote Login: Off" (sshd off = OK).
		// Apply must consume only that one call and return nil — no sudo disable call.
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "Remote Login: Off\n", ExitCode: 0}},
		)
		m := New(modules.Deps{Cfg: cfg, Runner: r})
		err := m.Apply(context.Background())
		assert.NoError(t, err, "Apply must not error when Remote Login is correctly off (SeverityOK path)")
		assert.True(t, r.Done(), "Apply must not issue any runner calls beyond the Detect probe")

	case "linux":
		// Detect calls systemctl is-active sshd → "inactive", then the NET-08
		// fallback probes ssh.service (also inactive). Apply must consume only
		// those two probes and return nil — no sudo disable call.
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 0}},
			shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 3}},
		)
		m := New(modules.Deps{Cfg: cfg, Runner: r})
		err := m.Apply(context.Background())
		assert.NoError(t, err, "Apply must not error when sshd is correctly off (SeverityOK path)")
		assert.True(t, r.Done(), "Apply must not issue any runner calls beyond the Detect probes")

	default:
		t.Skipf("TestApply_SeverityOK_NoMutation not applicable on %s", runtime.GOOS)
	}
}

// TestVerifyReturnsNil asserts that Verify returns nil findings and nil error
// (Pitfall-4 fix: Verify must not delegate to Detect to avoid double-emission).
func TestVerifyReturnsNil(t *testing.T) {
	// No mock calls expected — Verify must return nil without running any commands.
	r := shell.NewMockRunner()
	cfg := config.Defaults()
	cfg.Modules.SSH.Enabled = true
	cfg.Modules.SSH.Mode = "tailscale"
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Verify(context.Background())
	require.NoError(t, err, "Verify must not return an error")
	require.Empty(t, findings, "Verify must return nil/empty findings (no double-emission)")
}

// TestApply_NonOK_RunsMutation asserts that Apply still issues the disable
// mutation when the ssh finding is non-OK (sshd is on when it should be off).
func TestApply_NonOK_RunsMutation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"
	cfg.Modules.SSH.Enabled = true

	switch runtime.GOOS {
	case "darwin":
		// Detect call → systemsetup reports "Remote Login: On" (SeverityWarning).
		// Apply must then issue the "sudo systemsetup -setremotelogin off" call.
		r := shell.NewMockRunner(
			// Call 1: Detect → systemsetup -getremotelogin
			shell.Call{Result: shell.Result{Stdout: "Remote Login: On\n", ExitCode: 0}},
			// Call 2: Apply → sudo systemsetup -setremotelogin off
			shell.Call{Result: shell.Result{ExitCode: 0}},
		)
		m := New(modules.Deps{Cfg: cfg, Runner: r})
		err := m.Apply(context.Background())
		require.NoError(t, err, "Apply must succeed when disabling Remote Login returns exit 0")
		calls := r.RecordedCalls()
		require.Len(t, calls, 2, "Apply must issue exactly 2 runner calls: Detect + disable")
		assert.Equal(t, "sudo", calls[1].Name)
		assert.Contains(t, calls[1].Args, "-setremotelogin", "Apply must call systemsetup -setremotelogin off")

	case "linux":
		// Detect call → systemctl is-active sshd returns "active" (SeverityWarning).
		// Apply must then issue "sudo systemctl disable --now sshd".
		r := shell.NewMockRunner(
			// Call 1: Detect → systemctl is-active sshd
			shell.Call{Result: shell.Result{Stdout: "active\n", ExitCode: 0}},
			// Call 2: Apply → sudo systemctl disable --now sshd
			shell.Call{Result: shell.Result{ExitCode: 0}},
		)
		m := New(modules.Deps{Cfg: cfg, Runner: r})
		err := m.Apply(context.Background())
		require.NoError(t, err, "Apply must succeed when disabling sshd returns exit 0")
		calls := r.RecordedCalls()
		require.Len(t, calls, 2, "Apply must issue exactly 2 runner calls: Detect + disable")
		assert.Equal(t, "sudo", calls[1].Name)
		assert.Contains(t, calls[1].Args, "disable", "Apply must call systemctl disable")

	default:
		t.Skipf("TestApply_NonOK_RunsMutation not applicable on %s", runtime.GOOS)
	}
}

// TestParseRemoteLogin pins the exact-match parser (W4): only the literal
// "Remote Login: On"/"Remote Login: Off" status line is trusted; note lines,
// permission warnings, and error text yield unknown.
func TestParseRemoteLogin(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
	}{
		{"on", "Remote Login: On\n", remoteLoginOn},
		{"off", "Remote Login: Off\n", remoteLoginOff},
		{"on_with_note_lines", "### Notice: Full Disk Access permission is required\nRemote Login: On\n", remoteLoginOn},
		{"permission_warning_only", "You need administrator access to run this tool... exiting!\n", remoteLoginUnknown},
		{"word_containing_on", "Remote Login configuration unavailable\n", remoteLoginUnknown},
		{"empty", "", remoteLoginUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseRemoteLogin(tc.stdout))
		})
	}
}

// TestDetectDarwin_UnknownState asserts that unparseable systemsetup output
// (or a non-zero exit) emits the remote_login_unknown WARN finding — a check
// name Plan/Apply never map to the disable mutation (W4: no action on unknown).
func TestDetectDarwin_UnknownState(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"

	t.Run("noise_output", func(t *testing.T) {
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "### Notice: some permission warning\n", ExitCode: 0}},
		)
		m := New(modules.Deps{Cfg: cfg, Runner: r})
		findings := m.detectDarwin(context.Background())
		require.Len(t, findings, 1)
		assert.Equal(t, "remote_login_unknown", findings[0].Check)
		assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
	})

	t.Run("non_zero_exit_overrides_parsed_state", func(t *testing.T) {
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "Remote Login: On\n", ExitCode: 1}},
		)
		m := New(modules.Deps{Cfg: cfg, Runner: r})
		findings := m.detectDarwin(context.Background())
		require.Len(t, findings, 1)
		assert.Equal(t, "remote_login_unknown", findings[0].Check,
			"a non-zero systemsetup exit must never be parsed as state (W4)")
	})
}

// TestApply_UnknownRemoteLogin_NoMutation asserts that the unknown Remote
// Login state never triggers the `systemsetup -setremotelogin off` mutation.
func TestApply_UnknownRemoteLogin_NoMutation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Apply routes Detect through runtime.GOOS; darwin-only scenario")
	}
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"
	cfg.Modules.SSH.Enabled = true

	// Single scripted call: the Detect probe. A second (mutation) call would
	// make MockRunner return an error and fail the test.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "garbage output\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	require.NoError(t, m.Apply(context.Background()))
	assert.True(t, r.Done(), "unknown state must not trigger the disable mutation")
}

// newFallbackModule builds an ssh module in openssh-fallback mode with HOME
// pointed at a temp dir and a real (temp) audit writer.
func newFallbackModule(t *testing.T, r *shell.MockRunner) *Module {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfg := config.Defaults()
	cfg.Modules.SSH.Enabled = true
	cfg.Modules.SSH.Mode = "openssh-fallback"
	cfg.Identity.UnixUser = "alice"
	return New(modules.Deps{Cfg: cfg, Runner: r, Audit: audit.New(filepath.Join(dir, "audit.log"))})
}

// TestInstallHardenedSSHD_RemovesDropInOnValidationFailure is the W2
// regression test: when `sshd -t` rejects the freshly-installed drop-in, the
// drop-in must be removed again — otherwise the NEXT sshd restart (reboot,
// package upgrade) parses the broken config and locks the user out remotely.
func TestInstallHardenedSSHD_RemovesDropInOnValidationFailure(t *testing.T) {
	r := shell.NewMockRunner(
		// 1. sudo install -m 600 <staged> /etc/ssh/sshd_config.d/99-abysslink.conf
		shell.Call{Result: shell.Result{ExitCode: 0}},
		// 2. sudo sshd -t → invalid config
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "/etc/ssh/sshd_config.d/99-abysslink.conf: bad directive"}},
		// 3. rollback: sudo rm -f /etc/ssh/sshd_config.d/99-abysslink.conf
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := newFallbackModule(t, r)

	err := m.installHardenedSSHD(context.Background())
	require.Error(t, err, "validation failure must surface as an error")
	assert.Contains(t, err.Error(), "sshd config invalid")
	assert.Contains(t, err.Error(), "removed again", "the error must report the rollback")

	calls := r.RecordedCalls()
	require.Len(t, calls, 3, "install, validate, rollback — and NO reload")
	assert.Equal(t, "sudo", calls[2].Name)
	assert.Equal(t, []string{"rm", "-f", sshdDropInPath}, calls[2].Args,
		"the invalid drop-in must be removed after failed validation (W2)")
}

// TestInstallHardenedSSHD_RollbackFailureIsLoud asserts that when the rollback
// rm itself fails, the returned error tells the user to remove the file
// manually before the next sshd restart.
func TestInstallHardenedSSHD_RollbackFailureIsLoud(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}},                                  // install
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "bad directive"}},         // sshd -t
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "rm: permission denied"}}, // rm fails
	)
	m := newFallbackModule(t, r)

	err := m.installHardenedSSHD(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ROLLBACK FAILED")
	assert.Contains(t, err.Error(), sshdDropInPath)
}

// TestInstallHardenedSSHD_ValidConfigReloads pins the happy path: install,
// validate OK, reload — no rollback call.
func TestInstallHardenedSSHD_ValidConfigReloads(t *testing.T) {
	calls := []shell.Call{
		{Result: shell.Result{ExitCode: 0}}, // install
		{Result: shell.Result{ExitCode: 0}}, // sshd -t OK
		{Result: shell.Result{ExitCode: 0}}, // reload (launchctl on darwin / systemctl on linux)
	}
	r := shell.NewMockRunner(calls...)
	m := newFallbackModule(t, r)
	require.NoError(t, m.installHardenedSSHD(context.Background()))
	require.Len(t, r.RecordedCalls(), 3)
}

// TestInstallHardenedSSHD_RejectsUnsafeUnixUser is the W3 use-site guard:
// even if an unsafe unix_user slips past config validation (or arrives via the
// $USER fallback), the sshd config renderer must refuse to interpolate it.
func TestInstallHardenedSSHD_RejectsUnsafeUnixUser(t *testing.T) {
	unsafe := []string{
		"me\nPasswordAuthentication yes", // newline → sshd directive injection
		"alice bob",                      // whitespace → extra AllowUsers entry
		"",                               // empty (with $USER also empty) → AllowUsers with no operand
		"Alice",                          // uppercase — outside the POSIX-portable shape
	}
	for _, user := range unsafe {
		r := shell.NewMockRunner() // NO calls expected — must fail before any exec
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		// Neutralize the $USER fallback so the empty-user case stays empty —
		// and so a hostile $USER value is covered by the same use-site guard.
		t.Setenv("USER", "")
		cfg := config.Defaults()
		cfg.Modules.SSH.Enabled = true
		cfg.Modules.SSH.Mode = "openssh-fallback"
		cfg.Identity.UnixUser = user
		m := New(modules.Deps{Cfg: cfg, Runner: r, Audit: audit.New(filepath.Join(dir, "audit.log"))})

		err := m.installHardenedSSHD(context.Background())
		require.Error(t, err, "unsafe unix_user %q must be rejected", user)
		assert.Contains(t, err.Error(), "refusing to render sshd config")
		assert.Empty(t, r.RecordedCalls(), "no command may run for unsafe user %q", user)
	}
}

// TestApply_DisableSshd_ExecErrorReported asserts the real exec error is
// surfaced when systemctl cannot be executed at all — not a fabricated
// "exit 0" from the zero Result (review INFO).
func TestApply_DisableSshd_ExecErrorReported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Apply routes Detect through runtime.GOOS; linux-only scenario")
	}
	cfg := config.Defaults()
	cfg.Modules.SSH.Mode = "tailscale"
	cfg.Modules.SSH.Enabled = true

	r := shell.NewMockRunner(
		// Detect: systemctl is-active sshd → active
		shell.Call{Result: shell.Result{Stdout: "active\n", ExitCode: 0}},
		// Apply: sudo systemctl disable --now sshd → exec error (zero Result)
		shell.Call{Err: fmt.Errorf("exec: sudo: not found")},
		// Apply: sudo systemctl disable --now ssh → exec error too
		shell.Call{Err: fmt.Errorf("exec: sudo: not found")},
	)
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	err := m.Apply(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sudo: not found", "the real exec error must be in the message")
	assert.NotContains(t, err.Error(), "exit 0", "never fabricate an exit code from the zero Result")
}
