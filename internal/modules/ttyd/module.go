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

package ttyd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the ttyd optional module.
// ttyd provides a web-based terminal, bound to the tailnet IP only,
// secured with tailscale cert HTTPS.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new ttyd Module.
func New(runner shell.Runner, cfg *config.Config) *Module {
	return &Module{runner: runner, cfg: cfg}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "ttyd" }

// Deps returns the modules this module depends on.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect inspects the current system state for the ttyd installation.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.Ttyd.Enabled {
		slog.Debug("ttyd module disabled, skipping detect")
		return nil, nil
	}

	// Check whether ttyd binary is installed.
	res, err := m.runner.Run(ctx, "ttyd", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ttyd_installed",
			Severity: modules.SeverityFatal,
			Message:  "ttyd binary not found — install ttyd manually (see https://github.com/tsl0922/ttyd)",
		})
		return findings, nil
	}

	slog.Debug("ttyd version", "output", strings.TrimSpace(res.Stdout))

	// Check if ttyd is running and bound to the tailnet IP.
	// We inspect running processes for ttyd invocations binding to 0.0.0.0.
	res, err = m.runner.Run(ctx, "pgrep", "-a", "ttyd")
	if err == nil && res.ExitCode == 0 {
		output := res.Stdout
		if strings.Contains(output, "0.0.0.0") || strings.Contains(output, "::") {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "ttyd_bind_tailnet",
				Severity: modules.SeverityWarning,
				Message:  "ttyd appears to be bound to 0.0.0.0 or :: — it must bind to the tailnet IP only",
			})
		}
	}

	return findings, nil
}

// Plan computes the actions needed to reach the desired state.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Ttyd.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "ttyd_installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install ttyd (see https://github.com/tsl0922/ttyd#installation)",
				Reversible:  false,
			})
		case "ttyd_bind_tailnet":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "restart ttyd bound to tailnet IP only (not 0.0.0.0)",
				Reversible:  true,
			})
		}
	}

	actions = append(actions, modules.Action{
		Module:      m.Name(),
		Description: "configure ttyd with tailscale cert HTTPS bound to tailnet IP",
		Reversible:  true,
	})
	actions = append(actions, modules.Action{
		Module:      m.Name(),
		Description: "WARNING: ttyd basic-auth is required — do not expose without authentication",
		Reversible:  false,
	})

	return actions, nil
}

// Apply is not yet implemented — ttyd must be installed manually.
func (m *Module) Apply(_ context.Context) error {
	return fmt.Errorf("ttyd module: apply not yet implemented — install ttyd manually and re-run `abysslink up`")
}

// Verify re-runs Detect to confirm ttyd is correctly installed and bound.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
