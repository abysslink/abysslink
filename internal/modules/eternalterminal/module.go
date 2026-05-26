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

package eternalterminal

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

const (
	etACLPort = "tcp/2022"

	// Service unit paths per platform.
	systemdServicePath = "/etc/systemd/system/etserver.service"
	launchdPlistPath   = "/Library/LaunchDaemons/com.etserver.etserver.plist"
)

// Module implements the eternal-terminal optional module.
// It installs the ET client and server, and wires the ACL for tcp/2022.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new eternal-terminal Module.
func New(runner shell.Runner, cfg *config.Config) *Module {
	return &Module{runner: runner, cfg: cfg}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "eternal-terminal" }

// Deps returns the modules this module depends on.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect inspects the current system state for the ET installation.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.EternalTerminal.Enabled {
		slog.Debug("eternal-terminal module disabled, skipping detect")
		return nil, nil
	}

	// Check whether the ET client (et) binary is installed.
	res, err := m.runner.Run(ctx, "et", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "et_client_installed",
			Severity: modules.SeverityFatal,
			Message:  "ET client binary (et) not found — install eternal-terminal manually (see https://eternalterminal.dev)",
		})
	} else {
		slog.Debug("et client version", "output", strings.TrimSpace(res.Stdout))
	}

	// Check whether the ET server (etserver) binary is installed.
	res, err = m.runner.Run(ctx, "etserver", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "et_server_installed",
			Severity: modules.SeverityFatal,
			Message:  "ET server binary (etserver) not found — install eternal-terminal manually (see https://eternalterminal.dev)",
		})
	} else {
		slog.Debug("etserver version", "output", strings.TrimSpace(res.Stdout))
	}

	// Check whether the service unit is installed for this platform.
	serviceUnitFinding := m.detectServiceUnit(ctx)
	if serviceUnitFinding != nil {
		findings = append(findings, *serviceUnitFinding)
	}

	return findings, nil
}

// detectServiceUnit checks whether a platform service unit for etserver is installed.
func (m *Module) detectServiceUnit(_ context.Context) *modules.Finding {
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat(systemdServicePath); os.IsNotExist(err) {
			return &modules.Finding{
				Module:   m.Name(),
				Check:    "et_service_unit_installed",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("etserver systemd service unit not found at %s", systemdServicePath),
			}
		}
	case "darwin":
		if _, err := os.Stat(launchdPlistPath); os.IsNotExist(err) {
			return &modules.Finding{
				Module:   m.Name(),
				Check:    "et_service_unit_installed",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("etserver launchd plist not found at %s", launchdPlistPath),
			}
		}
	default:
		return &modules.Finding{
			Module:   m.Name(),
			Check:    "et_service_unit_installed",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("unsupported platform %q — cannot verify etserver service unit", runtime.GOOS),
		}
	}
	return nil
}

// Plan computes the actions needed to reach the desired state.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.EternalTerminal.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "et_client_installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install eternal-terminal client (et) — see https://eternalterminal.dev/downloads",
				Reversible:  false,
			})
		case "et_server_installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install eternal-terminal server (etserver) — see https://eternalterminal.dev/downloads",
				Reversible:  false,
			})
		case "et_service_unit_installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install etserver service unit (systemd or launchd)",
				Reversible:  true,
			})
		}
	}

	actions = append(actions, modules.Action{
		Module:      m.Name(),
		Description: fmt.Sprintf("grant ACL %s for eternal-terminal in Tailscale policy", etACLPort),
		Reversible:  false,
	})

	return actions, nil
}

// Apply is not yet implemented — eternal-terminal must be installed manually.
func (m *Module) Apply(_ context.Context) error {
	return fmt.Errorf("eternal-terminal module: apply not yet implemented — install ET manually and re-run `abysslink up`")
}

// Verify re-runs Detect to confirm eternal-terminal is correctly installed.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
