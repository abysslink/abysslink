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

package asciinema

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

// asciinemaConfig sets api_url to empty to disable cloud uploads by default.
const asciinemaConfig = `[api]
; url =
; Uploads are disabled by default. Set url = https://asciinema.org to enable,
; or point to a self-hosted instance.
`

// Module implements the optional Asciinema terminal-recording module.
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
func (m *Module) Name() string { return "asciinema" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return nil }

// Detect checks whether asciinema is installed and the config is safe.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Asciinema.Enabled {
		slog.Debug("asciinema module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "asciinema", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityWarning,
			Message:  "asciinema not found — install via package manager or https://asciinema.org/docs/installation",
		})
		return findings, nil
	}
	slog.Debug("asciinema version", "output", strings.TrimSpace(res.Stdout+res.Stderr))

	// Check config for cloud upload URL.
	cfgPath := asciinemaConfigPath()
	data, err := os.ReadFile(cfgPath) //nolint:gosec // G304: cfgPath is the module config path resolved internally, not user input
	if err == nil {
		content := string(data)
		// Warn if url is set to the public asciinema.org (privacy consideration).
		if strings.Contains(content, "url = https://asciinema.org") {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "no_cloud_upload",
				Severity: modules.SeverityWarning,
				Message:  "asciinema is configured to upload recordings to asciinema.org — consider a self-hosted instance or disable uploads",
			})
		}
	}

	return findings, nil
}

// Plan computes the actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Asciinema.Enabled {
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
				Description: "install asciinema",
				Reversible:  false,
			})
		case "no_cloud_upload":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "configure asciinema to disable cloud uploads",
				Reversible:  true,
			})
		}
	}

	if len(actions) == 0 {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "write asciinema config (cloud uploads disabled by default)",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply installs asciinema and writes a privacy-safe config.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Asciinema.Enabled {
		return nil
	}

	if res, err := m.runner.Run(ctx, "asciinema", "--version"); err != nil || res.ExitCode != 0 {
		slog.Info("asciinema apply: installing asciinema")
		if err := m.plat.InstallPackage(ctx, "asciinema"); err != nil {
			return fmt.Errorf("asciinema apply: install: %w", err)
		}
	}

	cfgPath := asciinemaConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("asciinema apply: mkdir config dir: %w", err)
	}

	// Only write if the file doesn't already exist.
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if m.audit == nil {
			return fmt.Errorf("asciinema apply: audit not available")
		}
		if err := m.audit.WriteFile(cfgPath, []byte(asciinemaConfig), 0o600, false); err != nil {
			return fmt.Errorf("asciinema apply: write config: %w", err)
		}
		slog.Info("asciinema apply: wrote privacy config (cloud uploads disabled)", "path", cfgPath)
	} else {
		slog.Debug("asciinema apply: config already exists, not overwriting", "path", cfgPath)
	}

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

// asciinemaConfigPath returns the OS-specific asciinema config path.
func asciinemaConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "asciinema", "config")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "asciinema", "config")
}
