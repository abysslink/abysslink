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

package upsnap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

const upsnapPort = "8090"

// Module implements the optional UpSnap Wake-on-LAN module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	plat   platform.Platform
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "upsnap" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect checks whether upsnap is installed and not binding to all interfaces.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Upsnap.Enabled {
		slog.Debug("upsnap module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "upsnap", "--version")
	if err != nil || res.ExitCode != 0 {
		// upsnap may print version to stderr; check both.
		combined := strings.ToLower(res.Stdout + res.Stderr)
		if !strings.Contains(combined, "upsnap") {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "installed",
				Severity: modules.SeverityFatal,
				Message:  "upsnap not found — install from https://github.com/seriousm4x/UpSnap/releases",
			})
			return findings, nil
		}
	}
	slog.Debug("upsnap detected")

	// Check running processes for wildcard bind.
	res, err = m.runner.Run(ctx, "pgrep", "-a", "upsnap")
	if err == nil && res.ExitCode == 0 {
		if strings.Contains(res.Stdout, "0.0.0.0") {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "bind_tailnet",
				Severity: modules.SeverityWarning,
				Message:  "upsnap appears bound to 0.0.0.0 — must bind to tailnet IP only",
			})
		}
	}

	return findings, nil
}

// Plan computes the actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Upsnap.Enabled {
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
				Description: "install upsnap (download from https://github.com/seriousm4x/UpSnap/releases)",
				Reversible:  false,
			})
		case "bind_tailnet":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: fmt.Sprintf("restart upsnap bound to tailnet IP:%s", upsnapPort),
				Reversible:  true,
			})
		}
	}

	if len(actions) == 0 {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: fmt.Sprintf("ensure upsnap service bound to tailnet IP:%s", upsnapPort),
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply installs upsnap and runs it bound to the tailnet IP.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Upsnap.Enabled {
		return nil
	}

	if res, err := m.runner.Run(ctx, "upsnap", "--version"); err != nil || res.ExitCode != 0 {
		combined := strings.ToLower(res.Stdout + res.Stderr)
		if !strings.Contains(combined, "upsnap") {
			slog.Info("upsnap apply: upsnap not found — install from https://github.com/seriousm4x/UpSnap/releases and ensure it is on PATH")
			return fmt.Errorf("upsnap apply: upsnap not on PATH — download from https://github.com/seriousm4x/UpSnap/releases and place in ~/.local/bin/upsnap")
		}
	}

	ip, err := modules.TailnetIP(ctx, m.runner)
	if err != nil {
		return fmt.Errorf("upsnap apply: %w", err)
	}

	if err := m.plat.ServiceInstall(ctx, platform.ServiceSpec{
		Label:     "dev.abysslink.upsnap",
		Args:      []string{"upsnap", "serve", "--http", fmt.Sprintf("%s:%s", ip, upsnapPort)},
		KeepAlive: true,
		RunAtLoad: true,
	}); err != nil {
		return fmt.Errorf("upsnap apply: install service: %w", err)
	}

	slog.Info("upsnap apply: service installed",
		"url", fmt.Sprintf("http://%s:%s", ip, upsnapPort),
		"note", "set an admin password on first login")
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
