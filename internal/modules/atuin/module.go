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

package atuin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// atuinConfig is the default config written when atuin is first set up.
// sync_address is intentionally empty — local-only mode, no cloud sync.
const atuinConfig = `## atuin config — managed by abysslink
[sync]
sync_address = ""

[history]
filter_mode = "global"

[keys]
scroll_exits = true
`

// Module implements the optional Atuin shell-history module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	plat   platform.Platform
	audit  audit.AuditWriter
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform, audit: d.Audit}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "atuin" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return nil }

// Detect checks whether atuin is installed.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Atuin.Enabled {
		slog.Debug("atuin module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "atuin", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityWarning,
			Message:  "atuin not found — install via package manager or https://atuin.sh",
		})
		return findings, nil
	}
	slog.Debug("atuin version", "output", strings.TrimSpace(res.Stdout+res.Stderr))

	// Check that sync_address is not pointing to the public cloud server.
	cfgPath := atuinConfigPath()
	data, err := os.ReadFile(cfgPath) //nolint:gosec // G304: cfgPath is the module config path resolved internally, not user input
	if err == nil {
		content := string(data)
		if strings.Contains(content, "api.atuin.sh") {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "no_cloud_sync",
				Severity: modules.SeverityWarning,
				Message:  "atuin is configured to sync with the public cloud (api.atuin.sh) — consider a self-hosted server or local-only mode",
			})
		}
	}

	return findings, nil
}

// Plan computes the actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Atuin.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install atuin",
				Reversible:  false,
			})
		case "no_cloud_sync":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "configure atuin for local-only mode (no cloud sync)",
				Reversible:  true,
			})
		}
	}

	if len(actions) == 0 {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "write atuin config (local-only, no cloud sync)",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply installs atuin and writes a local-only config.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Atuin.Enabled {
		return nil
	}

	if res, err := m.runner.Run(ctx, "atuin", "--version"); err != nil || res.ExitCode != 0 {
		slog.Info("atuin apply: installing atuin")
		if err := m.plat.InstallPackage(ctx, "atuin"); err != nil {
			return fmt.Errorf("atuin apply: install: %w", err)
		}
	}

	cfgPath := atuinConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("atuin apply: mkdir config dir: %w", err)
	}

	// Only write the config if it doesn't already exist to avoid clobbering
	// user customisations.
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if m.audit == nil {
			return fmt.Errorf("atuin apply: audit not available")
		}
		if err := m.audit.WriteFile(cfgPath, []byte(atuinConfig), 0o600, false); err != nil {
			return fmt.Errorf("atuin apply: write config: %w", err)
		}
		slog.Info("atuin apply: wrote local-only config", "path", cfgPath)
	} else {
		slog.Debug("atuin apply: config already exists, not overwriting", "path", cfgPath)
	}

	slog.Info("atuin apply: add `eval \"$(atuin init zsh)\"` to ~/.zshrc to enable shell integration")
	return nil
}

// Verify re-runs Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// atuinConfigPath returns the OS-specific atuin config path.
func atuinConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "atuin", "config.toml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "atuin", "config.toml")
}
