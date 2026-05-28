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
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the mosh module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the module name.
func (m *Module) Name() string { return "mosh" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect checks whether mosh-server is installed.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "mosh-server", "--version")
	if err != nil || res.ExitCode != 0 {
		// Some versions print version to stderr and exit non-zero; check both.
		combined := res.Stdout + res.Stderr
		if !strings.Contains(strings.ToLower(combined), "mosh") {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "installed",
				Severity: modules.SeverityWarning,
				Message:  "mosh-server is not installed or not on PATH",
			})
			return findings, nil
		}
	}
	slog.Debug("mosh-server detected", "output", strings.TrimSpace(res.Stdout+res.Stderr))

	return findings, nil
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Mosh.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		if f.Check == "installed" {
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install mosh",
				Reversible:  false,
			})
		}
	}

	return actions, nil
}

// Apply executes planned changes.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Mosh.Enabled {
		return nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return fmt.Errorf("mosh apply: detect: %w", err)
	}

	for _, f := range findings {
		if f.Check != "installed" {
			continue
		}
		slog.Info("mosh apply: installing mosh-server")
		switch runtime.GOOS {
		case "darwin":
			res, err := m.runner.Run(ctx, "brew", "install", "mosh")
			if err != nil {
				return fmt.Errorf("mosh apply: brew install mosh: %w", err)
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("mosh apply: brew install mosh exited %d: %s", res.ExitCode, res.Stderr)
			}
		case "linux":
			installed := false
			for _, args := range [][]string{
				{"apt-get", "install", "-y", "mosh"},
				{"dnf", "install", "-y", "mosh"},
				{"pacman", "-Sy", "--noconfirm", "mosh"},
			} {
				res, err := m.runner.Run(ctx, "sudo", args...)
				if err == nil && res.ExitCode == 0 {
					installed = true
					break
				}
			}
			if !installed {
				return fmt.Errorf("mosh apply: could not install mosh — no supported package manager found")
			}
		default:
			return fmt.Errorf("mosh apply: unsupported OS %q", runtime.GOOS)
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
