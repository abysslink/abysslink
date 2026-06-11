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
	"path/filepath"
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

const (
	etACLPort = "tcp/2022"

	// etServiceLabel is the USER-level service unit Apply installs via
	// platform.ServiceInstall. Detect must look for exactly this unit (W5):
	// checking system paths (/etc/systemd/system, /Library/LaunchDaemons)
	// that Apply never writes made the warning permanent.
	etServiceLabel = "dev.abysslink.etserver"
)

// etServiceUnitPath returns the path platform.ServiceInstall writes for
// etServiceLabel on this OS ("" for unsupported platforms):
//   - linux:  ~/.config/systemd/user/<label>.service
//   - darwin: ~/Library/LaunchAgents/<label>.plist
func etServiceUnitPath(goos string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	switch goos {
	case "linux":
		return filepath.Join(home, ".config", "systemd", "user", etServiceLabel+".service"), nil
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", etServiceLabel+".plist"), nil
	default:
		return "", nil
	}
}

// Module implements the eternal-terminal optional module.
// It installs the ET client and server, and wires the ACL for tcp/2022.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	plat   platform.Platform
}

// New returns a new eternal-terminal Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform}
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

// detectServiceUnit checks whether the user-level service unit Apply manages
// (etServiceLabel via platform.ServiceInstall) is installed. It must inspect
// the SAME unit Apply writes — Detect previously checked system unit paths
// Apply never touches, so the warning persisted forever after a successful
// Apply (W5).
func (m *Module) detectServiceUnit(_ context.Context) *modules.Finding {
	unitPath, err := etServiceUnitPath(runtime.GOOS)
	if err != nil {
		return &modules.Finding{
			Module:   m.Name(),
			Check:    "et_service_unit_installed",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("cannot resolve etserver service unit path: %v", err),
		}
	}
	if unitPath == "" {
		return &modules.Finding{
			Module:   m.Name(),
			Check:    "et_service_unit_installed",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("unsupported platform %q — cannot verify etserver service unit", runtime.GOOS),
		}
	}
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return &modules.Finding{
			Module:   m.Name(),
			Check:    "et_service_unit_installed",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("etserver service unit (%s) not found at %s", etServiceLabel, unitPath),
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

// Apply installs eternal-terminal and runs etserver on tcp/2022. ET is a
// TCP-based mosh alternative for networks that block UDP; access is still
// gated by the tailnet ACL (etACLPort).
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.EternalTerminal.Enabled {
		return nil
	}

	// Gate the install on BOTH binaries: the service below runs `etserver`,
	// so a present client (`et`) with a missing server must still trigger the
	// package install — otherwise we register a service pointing at a
	// nonexistent binary (W5b). The check short-circuits: when `et` is
	// already missing there is no need to probe `etserver`.
	if !m.binaryPresent(ctx, "et") || !m.binaryPresent(ctx, "etserver") {
		slog.Info("eternal-terminal apply: installing eternal-terminal")
		if err := m.plat.InstallPackage(ctx, "eternal-terminal"); err != nil {
			return fmt.Errorf("eternal-terminal apply: install: %w", err)
		}
	}

	if err := m.plat.ServiceInstall(ctx, platform.ServiceSpec{
		Label:     etServiceLabel,
		Args:      []string{"etserver", "--port", "2022"},
		KeepAlive: true,
		RunAtLoad: true,
	}); err != nil {
		return fmt.Errorf("eternal-terminal apply: install service: %w", err)
	}
	slog.Info("eternal-terminal apply: etserver installed on tcp/2022 (grant " + etACLPort + " in the tailnet ACL)")
	return nil
}

// binaryPresent reports whether `name --version` runs successfully.
func (m *Module) binaryPresent(ctx context.Context, name string) bool {
	res, err := m.runner.Run(ctx, name, "--version")
	return err == nil && res.Ok()
}

// Verify is a no-op for the eternal-terminal module — all checks run in Detect.
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
