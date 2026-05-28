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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the mosh module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	audit  *audit.Audit
	plat   platform.Platform
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, audit: d.Audit, plat: d.Platform}
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
		if err := m.plat.InstallPackage(ctx, "mosh"); err != nil {
			return fmt.Errorf("mosh apply: install mosh: %w", err)
		}
	}

	// On macOS, mosh-server installs under the Homebrew prefix, which is not on
	// the PATH of a non-login SSH shell — so `mosh host` fails with "mosh-server
	// not found". Ensure the prefix is exported from ~/.zshenv (read by all zsh
	// invocations, including non-login). Linux installs to /usr/bin (already on
	// PATH), so this is a no-op there.
	if runtime.GOOS == "darwin" {
		if err := m.ensureZshenvPath(ctx); err != nil {
			slog.Warn("mosh apply: could not ensure ~/.zshenv PATH; `mosh` over SSH may not find mosh-server", "err", err)
		}
	}

	return nil
}

// ensureZshenvPath idempotently adds the Homebrew bin directory to PATH in
// ~/.zshenv so non-login shells (used by mosh/ssh) can resolve mosh-server.
func (m *Module) ensureZshenvPath(ctx context.Context) error {
	res, err := m.runner.Run(ctx, "brew", "--prefix")
	if err != nil || res.ExitCode != 0 {
		return fmt.Errorf("brew --prefix: %w", err)
	}
	binDir := filepath.Join(strings.TrimSpace(res.Stdout), "bin")
	if binDir == "/bin" { // empty prefix guard
		return fmt.Errorf("brew --prefix returned empty output")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home dir: %w", err)
	}
	zshenv := filepath.Join(home, ".zshenv")

	existing, _ := os.ReadFile(zshenv) //nolint:gosec // user home path
	if strings.Contains(string(existing), "abysslink managed") {
		slog.Debug("mosh apply: ~/.zshenv already has abysslink PATH block")
		return nil
	}

	block := fmt.Sprintf("\n# --- abysslink managed ---\nexport PATH=\"%s:$PATH\"\n# --- end abysslink managed ---\n", binDir)
	content := string(existing)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += block

	return m.audit.WriteFile(zshenv, []byte(content), 0o600, false)
}

// Verify re-runs Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
