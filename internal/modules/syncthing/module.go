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

package syncthing

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

const (
	synthingyGUIPort  = "8384"
	syncthingSyncPort = "22000"
)

// Module implements the optional Syncthing file-sync module.
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
func (m *Module) Name() string { return "syncthing" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect checks whether syncthing is installed and correctly configured.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Syncthing.Enabled {
		slog.Debug("syncthing module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "syncthing", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityFatal,
			Message:  "syncthing not found — install via package manager or https://syncthing.net",
		})
		return findings, nil
	}
	slog.Debug("syncthing version", "output", strings.TrimSpace(res.Stdout+res.Stderr))

	// Check GUI bind address in the config XML.
	cfgPath := syncthingConfigPath()
	data, err := os.ReadFile(cfgPath) //nolint:gosec // G304: cfgPath is the module config path resolved internally, not user input
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("syncthing detect: cannot read config", "path", cfgPath, "err", err)
		}
		// Config not yet generated — syncthing hasn't run yet; that's OK.
		return findings, nil
	}

	content := string(data)
	if strings.Contains(content, "<address>0.0.0.0:") ||
		strings.Contains(content, "<address>*:") ||
		strings.Contains(content, "<address>::") {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "gui_bind_tailnet",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("syncthing GUI is bound to all interfaces — must bind to tailnet IP only (%s)", cfgPath),
		})
	}

	return findings, nil
}

// Plan computes the actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Syncthing.Enabled {
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
				Description: "install syncthing",
				Reversible:  false,
			})
		case "gui_bind_tailnet":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: fmt.Sprintf("configure syncthing GUI to bind to tailnet IP only (port %s)", synthingyGUIPort),
				Reversible:  true,
			})
		}
	}

	if len(actions) == 0 {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: fmt.Sprintf("ensure syncthing service running, GUI on tailnet IP:%s", synthingyGUIPort),
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply installs syncthing and configures the GUI to bind to the tailnet IP.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Syncthing.Enabled {
		return nil
	}

	if res, err := m.runner.Run(ctx, "syncthing", "--version"); err != nil || res.ExitCode != 0 {
		slog.Info("syncthing apply: installing syncthing")
		if err := m.plat.InstallPackage(ctx, "syncthing"); err != nil {
			return fmt.Errorf("syncthing apply: install: %w", err)
		}
	}

	ip, err := modules.TailnetIP(ctx, m.runner)
	if err != nil {
		return fmt.Errorf("syncthing apply: %w", err)
	}

	// Install as a user service. Syncthing generates its own config on first run;
	// the GUI address is overridden via the --gui-address flag so we never need
	// to parse the XML.
	if err := m.plat.ServiceInstall(ctx, platform.ServiceSpec{
		Label: "dev.abysslink.syncthing",
		Args: []string{
			"syncthing",
			"--no-browser",
			fmt.Sprintf("--gui-address=%s:%s", ip, synthingyGUIPort),
		},
		KeepAlive: true,
		RunAtLoad: true,
	}); err != nil {
		return fmt.Errorf("syncthing apply: install service: %w", err)
	}

	slog.Info("syncthing apply: service installed",
		"gui_url", fmt.Sprintf("http://%s:%s", ip, synthingyGUIPort),
		"note", "set a GUI password in the web UI — the tailnet ACL is the outer boundary")
	return nil
}

// Verify is a no-op for the syncthing module — all checks run in Detect.
// Pitfall 4 (Doctor double-emission): do NOT call Detect here — runner.Doctor
// calls both Detect and Verify, so re-running Detect would double-emit every
// Detect finding per doctor pass (NET-18). Verify adds no new information
// beyond Detect; returning nil avoids the duplication (mirrors ssh/ntfy).
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// syncthingConfigPath returns the OS-specific syncthing config file path.
func syncthingConfigPath() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Syncthing", "config.xml")
	default:
		return filepath.Join(home, ".config", "syncthing", "config.xml")
	}
}
