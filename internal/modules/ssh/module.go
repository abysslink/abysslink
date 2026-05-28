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
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// sshdDropInPath is where the hardened openssh-fallback config is installed.
const sshdDropInPath = "/etc/ssh/sshd_config.d/99-abysslink.conf"

// Module implements the ssh module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	audit  *audit.Audit
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, audit: d.Audit}
}

// sshUser returns the configured UNIX user, falling back to $USER.
func (m *Module) sshUser() string {
	if m.cfg.Identity.UnixUser != "" {
		return m.cfg.Identity.UnixUser
	}
	return os.Getenv("USER")
}

// Name returns the module name.
func (m *Module) Name() string { return "ssh" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect inspects the current SSH configuration state.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.SSH.Enabled {
		slog.Debug("ssh module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	switch runtime.GOOS {
	case "darwin":
		findings = append(findings, m.detectDarwin(ctx)...)
	case "linux":
		findings = append(findings, m.detectLinux(ctx)...)
	default:
		slog.Warn("ssh detect: unsupported OS", "os", runtime.GOOS)
	}

	// openssh-fallback mode requires the hardened drop-in config to be installed.
	if m.cfg.Modules.SSH.Mode == "openssh-fallback" {
		if _, err := os.Stat(sshdDropInPath); err != nil {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "fallback_config",
				Severity: modules.SeverityWarning,
				Message:  "hardened sshd config " + sshdDropInPath + " is not installed",
			})
		}
	}

	return findings, nil
}

// detectDarwin checks macOS Remote Login state.
func (m *Module) detectDarwin(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "systemsetup", "-getremotelogin")
	if err != nil {
		slog.Warn("ssh detect: systemsetup failed", "error", err)
		return findings
	}

	output := strings.TrimSpace(res.Stdout)
	slog.Debug("ssh detect darwin", "remote_login", output)

	if m.cfg.Modules.SSH.Mode == "tailscale" {
		// When using Tailscale SSH, Remote Login (openssh daemon) should be off.
		if strings.Contains(strings.ToLower(output), "on") {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "remote_login",
				Severity: modules.SeverityWarning,
				Message:  "Remote Login is On — when mode=tailscale, macOS sshd should be disabled",
			})
		}
	}

	return findings
}

// detectLinux checks if sshd is running on Linux.
func (m *Module) detectLinux(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "systemctl", "is-active", "sshd")
	if err != nil {
		// Try ssh.service as alternate name.
		res, err = m.runner.Run(ctx, "systemctl", "is-active", "ssh")
		if err != nil {
			slog.Warn("ssh detect: systemctl failed", "error", err)
			return findings
		}
	}

	active := strings.TrimSpace(res.Stdout) == "active"
	slog.Debug("ssh detect linux", "sshd_active", active)

	if m.cfg.Modules.SSH.Mode == "tailscale" && active {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "sshd_running",
			Severity: modules.SeverityWarning,
			Message:  "sshd is running — when mode=tailscale, consider disabling the openssh daemon",
		})
	}

	return findings
}

// Plan computes the actions needed to reach the desired state.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.SSH.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch m.cfg.Modules.SSH.Mode {
		case "tailscale":
			if f.Check == "remote_login" || f.Check == "sshd_running" {
				actions = append(actions, modules.Action{
					Module:      m.Name(),
					Description: "disable Remote Login (use Tailscale SSH)",
					Reversible:  true,
				})
			}
		case "openssh-fallback":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "write hardened sshd_config.d/99-abysslink.conf",
				Reversible:  true,
			})
		}
	}

	return actions, nil
}

// Apply executes planned changes.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.SSH.Enabled {
		return nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return fmt.Errorf("ssh apply: detect: %w", err)
	}

	for _, f := range findings {
		switch f.Check {
		case "remote_login":
			// Disable macOS Remote Login — Tailscale SSH handles auth.
			slog.Info("ssh apply: disabling macOS Remote Login")
			res, err := m.runner.Run(ctx, "sudo", "systemsetup", "-setremotelogin", "off")
			if err != nil {
				return fmt.Errorf("ssh apply: disable remote login: %w", err)
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("ssh apply: disable remote login exited %d: %s", res.ExitCode, res.Stderr)
			}
		case "sshd_running":
			// Stop and disable sshd on Linux — Tailscale SSH handles auth.
			// Try both unit names (distros differ); error only if both fail.
			slog.Info("ssh apply: stopping sshd (Tailscale SSH mode)")
			var disableErr error
			for _, unit := range []string{"sshd", "ssh"} {
				res, err := m.runner.Run(ctx, "sudo", "systemctl", "disable", "--now", unit)
				if err == nil && res.ExitCode == 0 {
					disableErr = nil
					break
				}
				disableErr = fmt.Errorf("systemctl disable %s: exit %d: %s", unit, res.ExitCode, strings.TrimSpace(res.Stderr))
			}
			if disableErr != nil {
				return fmt.Errorf("ssh apply: could not disable sshd (tried sshd and ssh units): %w", disableErr)
			}
		case "fallback_config":
			if err := m.installHardenedSSHD(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

// hardenedSSHDConfig returns the sshd drop-in for openssh-fallback mode. It
// disables passwords and agent/TCP/X11 forwarding (so a compromised phone
// cannot pivot through a forwarded agent) and restricts logins to one user.
func hardenedSSHDConfig(user string) string {
	return fmt.Sprintf(`# Managed by abysslink — hardened sshd (openssh-fallback mode). Do not edit.
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
AllowUsers %s
`, user)
}

// installHardenedSSHD renders the hardened config, records it in the audit log,
// installs it as root, validates it with `sshd -t`, and reloads sshd. The
// config is validated BEFORE reload so a bad config never takes effect.
func (m *Module) installHardenedSSHD(ctx context.Context) error {
	content := hardenedSSHDConfig(m.sshUser())

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("ssh apply: home dir: %w", err)
	}
	staged := filepath.Join(home, ".config", "abysslink", "generated", "99-abysslink.conf")
	if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		return fmt.Errorf("ssh apply: mkdir generated: %w", err)
	}
	if err := m.audit.WriteFile(staged, []byte(content), 0o600, false); err != nil {
		return fmt.Errorf("ssh apply: stage config: %w", err)
	}

	slog.Info("ssh apply: installing hardened sshd config", "dest", sshdDropInPath)
	if res, err := m.runner.Run(ctx, "sudo", "install", "-m", "600", staged, sshdDropInPath); err != nil {
		return fmt.Errorf("ssh apply: install config: %w", err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("ssh apply: install config exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	// Validate before reloading — never activate a broken sshd config.
	if res, err := m.runner.Run(ctx, "sudo", "sshd", "-t"); err != nil {
		return fmt.Errorf("ssh apply: validate sshd config: %w", err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("ssh apply: sshd config invalid, not reloading: %s", strings.TrimSpace(res.Stderr))
	}

	for _, unit := range []string{"sshd", "ssh"} {
		if res, err := m.runner.Run(ctx, "sudo", "systemctl", "reload", unit); err == nil && res.ExitCode == 0 {
			break
		}
	}
	return nil
}

// Verify re-runs Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
