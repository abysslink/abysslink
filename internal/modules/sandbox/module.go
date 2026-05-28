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

package sandbox

import (
	"context"
	"log/slog"
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module detects OS-level process isolation capabilities for remote-access services.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "sandbox" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return nil }

// Detect checks whether process isolation tools are available.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Sandbox.Enabled {
		slog.Debug("sandbox module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	switch runtime.GOOS {
	case "darwin":
		findings = append(findings, m.detectDarwin(ctx)...)
	case "linux":
		findings = append(findings, m.detectLinux(ctx)...)
	default:
		slog.Warn("sandbox detect: unsupported OS", "os", runtime.GOOS)
	}

	return findings, nil
}

func (m *Module) detectDarwin(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	// sandbox-exec is the macOS userspace sandbox tool.
	res, err := m.runner.Run(ctx, "sandbox-exec", "-n", "no-internet", "/bin/true")
	if err != nil || (res.ExitCode != 0 && !strings.Contains(res.Stderr, "profile")) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "sandbox_exec_available",
			Severity: modules.SeverityWarning,
			Message:  "sandbox-exec not available — macOS process sandboxing cannot be applied to remote services",
		})
	} else {
		slog.Debug("sandbox detect: sandbox-exec available")
	}

	return findings
}

func (m *Module) detectLinux(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	// Check for firejail (user-space sandboxing).
	res, err := m.runner.Run(ctx, "firejail", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "firejail_available",
			Severity: modules.SeverityWarning,
			Message:  "firejail not found — install it to enable process sandboxing for remote services: sudo apt install firejail",
		})
	} else {
		slog.Debug("sandbox detect: firejail available")
	}

	// Check if systemd is available for sandboxing via service directives.
	res, err = m.runner.Run(ctx, "systemctl", "--user", "status")
	if err == nil && res.ExitCode <= 3 {
		slog.Debug("sandbox detect: systemd --user available for service sandboxing")
	}

	return findings
}

// Plan returns no auto-apply actions — sandbox profiles require operator review.
func (m *Module) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Sandbox.Enabled {
		return nil, nil
	}
	return []modules.Action{{
		Module:      m.Name(),
		Description: "sandbox profiles require manual review — run `abysslink doctor` and apply profiles per the security guide",
		Reversible:  false,
	}}, nil
}

// Apply is intentionally a no-op — sandbox profiles are operator-applied.
func (m *Module) Apply(_ context.Context) error { return nil }

// Verify re-runs Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair is a no-op.
func (m *Module) Repair(_ context.Context) error { return nil }
