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
