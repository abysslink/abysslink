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
	"runtime"
	"testing"

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

	// systemctl is-active sshd → "inactive"
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 0}},
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
		// Detect calls systemctl is-active sshd → "inactive" (sshd off = OK).
		// Apply must consume only that one call and return nil — no sudo disable call.
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 0}},
		)
		m := New(modules.Deps{Cfg: cfg, Runner: r})
		err := m.Apply(context.Background())
		assert.NoError(t, err, "Apply must not error when sshd is correctly off (SeverityOK path)")
		assert.True(t, r.Done(), "Apply must not issue any runner calls beyond the Detect probe")

	default:
		t.Skipf("TestApply_SeverityOK_NoMutation not applicable on %s", runtime.GOOS)
	}
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
