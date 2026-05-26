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

package tmux

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// minMajor and minMinor define the minimum acceptable tmux version.
const (
	minMajor = 3
	minMinor = 0
)

// Module implements the tmux module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(runner shell.Runner, cfg *config.Config) *Module {
	return &Module{runner: runner, cfg: cfg}
}

// Name returns the module name.
func (m *Module) Name() string { return "tmux" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{} }

// Detect checks the current tmux state.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "tmux", "-V")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityWarning,
			Message:  "tmux is not installed or not on PATH",
		})
		return findings, nil
	}

	// Parse version from output like "tmux 3.3a".
	output := strings.TrimSpace(res.Stdout)
	slog.Debug("tmux version", "output", output)

	major, minor, err := parseTmuxVersion(output)
	if err != nil {
		slog.Warn("tmux detect: could not parse version", "output", output, "error", err)
		// Don't fail hard — just warn.
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "version",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("could not parse tmux version from %q", output),
		})
		return findings, nil
	}

	if major < minMajor || (major == minMajor && minor < minMinor) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "version",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("tmux %d.%d is older than required %d.%d", major, minor, minMajor, minMinor),
		})
	}

	return findings, nil
}

// parseTmuxVersion parses "tmux 3.3a" into (3, 3).
func parseTmuxVersion(output string) (int, int, error) {
	parts := strings.Fields(output)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unexpected format: %q", output)
	}
	versionStr := parts[1]
	// Strip trailing non-numeric suffix (e.g. "3.3a" → "3.3").
	for len(versionStr) > 0 && (versionStr[len(versionStr)-1] < '0' || versionStr[len(versionStr)-1] > '9') {
		versionStr = versionStr[:len(versionStr)-1]
	}
	dotParts := strings.SplitN(versionStr, ".", 2)
	if len(dotParts) < 2 {
		return 0, 0, fmt.Errorf("no dot in version %q", versionStr)
	}
	major, err := strconv.Atoi(dotParts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("parse major: %w", err)
	}
	minor, err := strconv.Atoi(dotParts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parse minor: %w", err)
	}
	return major, minor, nil
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
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
				Description: "install tmux",
				Reversible:  false,
			})
		case "version":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: fmt.Sprintf("upgrade tmux to >= %d.%d", minMajor, minMinor),
				Reversible:  false,
			})
		}
	}

	// Always plan to write ~/.tmux.conf if the module is enabled.
	if m.cfg.Modules.Tmux.Enabled {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "write ~/.tmux.conf if changed",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply executes planned changes.
func (m *Module) Apply(_ context.Context) error {
	return fmt.Errorf("tmux module: apply not yet implemented")
}

// Verify re-runs Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
