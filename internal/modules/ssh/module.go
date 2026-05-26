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
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the ssh module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(runner shell.Runner, cfg *config.Config) *Module {
	return &Module{runner: runner, cfg: cfg}
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
func (m *Module) Apply(_ context.Context) error {
	return fmt.Errorf("ssh module: apply not yet implemented")
}

// Verify re-runs Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
