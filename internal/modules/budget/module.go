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

package budget

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
)

// Module implements the install-time Detect/Plan/Apply/Verify config shim for
// the budget: YAML block. It satisfies modules.Module (Name/Deps/Detect/Plan/Apply/Verify/Repair).
//
// This is the config-shape half of the D-01a two-part split for KILL-01.
// The runtime watcher engine lives at internal/budget (separate package).
// This module must NEVER import internal/budget or internal/modules/claudecode.
type Module struct {
	cfg        *config.Config
	audit      audit.AuditWriter
	configPath string // override for tests; empty = compute from os.UserHomeDir
}

// New returns a new budget Module from the given Deps.
// The abysslink.yaml config path is derived from $XDG_CONFIG_HOME or ~/.config/abysslink/abysslink.yaml.
func New(d modules.Deps) *Module {
	return &Module{cfg: d.Cfg, audit: d.Audit}
}

// NewWithConfigPath returns a budget Module with an explicit config file path.
// Used in tests to direct Apply to a temporary file instead of the real config location.
func NewWithConfigPath(d modules.Deps, configPath string) *Module {
	return &Module{cfg: d.Cfg, audit: d.Audit, configPath: configPath}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "budget" }

// Deps returns the module's dependencies. Budget is a config-only shim with no
// module-level dependencies — it validates fields already in abysslink.yaml.
func (m *Module) Deps() []string { return nil }

// isBudgetZero returns true when the Budget config block is entirely zero-value
// (all integer fields zero, Ladder false, TokenTiers nil). This means the budget:
// block is absent from abysslink.yaml (or was not written yet).
func isBudgetZero(b config.BudgetConfig) bool {
	return b.WallClockMinutes == 0 &&
		b.LoopN == 0 &&
		b.LoopWindow == 0 &&
		!b.Ladder &&
		b.KillGraceSeconds == 0 &&
		b.TokenTiers == nil
}

// Detect inspects the current Budget config and returns findings.
//
// Rules (defense-in-depth on top of config.validateBudget which runs at load time):
//   - Zero-value Budget block (block absent) → no findings (not configured is not an error).
//   - WallClockMinutes != 0 && WallClockMinutes < 1 → SeverityFatal.
//   - LoopN != 0 && LoopN < 2 → SeverityFatal.
//   - KillGraceSeconds != 0 && (< 1 || > 30) → SeverityFatal.
//   - Ladder == true → SeverityWarning (shadow mode recommended for first-time setup).
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	if m.cfg == nil {
		return nil, nil
	}
	b := m.cfg.Budget

	// Zero-value block: not configured yet, no findings.
	if isBudgetZero(b) {
		return nil, nil
	}

	var findings []modules.Finding

	if b.WallClockMinutes != 0 && b.WallClockMinutes < 1 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "wall_clock_minutes",
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("budget.wall_clock_minutes %d must be >= 1 (or 0 to use the default 30m)", b.WallClockMinutes),
		})
	}

	if b.LoopN != 0 && b.LoopN < 2 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "loop_n",
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("budget.loop_n %d must be >= 2 (or 0 to use the default 8)", b.LoopN),
		})
	}

	if g := b.KillGraceSeconds; g != 0 && (g < 1 || g > 30) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "kill_grace_seconds",
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("budget.kill_grace_seconds %d must be between 1 and 30 (or 0 to use the default 5s)", g),
		})
	}

	if b.Ladder {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ladder_enabled",
			Severity: modules.SeverityWarning,
			Message:  "budget.ladder is true — full kill ladder enabled; shadow mode (false) is recommended for first-time setup",
		})
	}

	return findings, nil
}

// Plan computes the actions needed to reach the desired state.
//
// Rules:
//   - Zero-value Budget block → action to add it with shadow-mode defaults.
//   - Fatal findings → action per finding to fix the offending field.
//   - No fatal findings AND non-zero Budget → no actions.
//
// Warning findings (e.g. ladder_enabled) are informational; they do not trigger
// Plan actions because the user explicitly opted in (Ladder:true is not an error).
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if m.cfg == nil {
		return nil, nil
	}

	// Zero-value block: budget not configured yet → offer to add it.
	if isBudgetZero(m.cfg.Budget) {
		return []modules.Action{{
			Module:      m.Name(),
			Description: "add budget: block to abysslink.yaml with shadow-mode defaults (wall_clock_minutes:30, loop_n:8, loop_window:20, kill_grace_seconds:5, ladder:false)",
			Reversible:  false,
		}}, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		if f.Severity != modules.SeverityFatal {
			continue
		}
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "fix budget." + f.Check + " in abysslink.yaml: " + f.Message,
			Reversible:  false,
		})
	}

	return actions, nil
}

// shadowModeDefaults is the budget: YAML block with shadow-mode defaults (D-05).
// These values are written by Apply when the block is absent from abysslink.yaml.
const shadowModeDefaults = `budget:
  # wall_clock_minutes: wall-clock run limit before a threshold trip.
  # Zero means default 30m. Floor 1m.
  wall_clock_minutes: 30
  # loop_n: number of identical closure-hash repeats in the sliding window
  # that constitutes a loop. Zero means default 8. Floor 2.
  loop_n: 8
  # loop_window: command-count sliding window size. Zero means default 20.
  loop_window: 20
  # kill_grace_seconds: SIGTERM grace period before SIGKILL in the kill ladder.
  # Zero means default 5. Floor 1, ceiling 30.
  kill_grace_seconds: 5
  # ladder: enables the full escalation ladder (notify → SIGSTOP → kill).
  # Default false (shadow mode — D-05). Set true to enable SIGSTOP on threshold.
  ladder: false
`

// resolveConfigPath returns the path to abysslink.yaml. It honours:
//  1. m.configPath if explicitly set (test injection).
//  2. $XDG_CONFIG_HOME/abysslink/abysslink.yaml if XDG_CONFIG_HOME is set.
//  3. ~/.config/abysslink/abysslink.yaml (default).
//
// This mirrors the CLI's defaultConfigPath() in internal/cli/root.go without
// importing the CLI layer (which would create an import cycle).
func (m *Module) resolveConfigPath() (string, error) {
	if m.configPath != "" {
		return m.configPath, nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "abysslink", "abysslink.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("budget apply: get home dir: %w", err)
	}
	return filepath.Join(home, ".config", "abysslink", "abysslink.yaml"), nil
}

// Apply writes the budget: block with shadow-mode defaults to abysslink.yaml
// via audit.AuditWriter.WriteFile (never raw os.WriteFile — CLAUDE.md invariant).
//
// THREAT: T-31-17 — the write is recorded in the audit chain; the audit writer
// creates a backup and appends an entry before writing.
func (m *Module) Apply(ctx context.Context) error {
	if m.audit == nil {
		return fmt.Errorf("budget apply: audit writer is nil")
	}

	cfgPath, err := m.resolveConfigPath()
	if err != nil {
		return err
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("budget apply: mkdir %s: %w", filepath.Dir(cfgPath), err)
	}

	slog.Info("budget apply: writing budget: block to config", "path", cfgPath)

	// WriteFile records the mutation in the audit chain AND writes atomically.
	// This satisfies T-31-17 and the CLAUDE.md invariant (no direct os.WriteFile).
	if err := m.audit.WriteFile(cfgPath, []byte(shadowModeDefaults), 0o600, false); err != nil {
		return fmt.Errorf("budget apply: write config: %w", err)
	}

	return nil
}

// Verify re-runs Detect and returns its findings.
//
// Re-using Detect is safe here: budget Detect is lightweight (no network or
// subprocess calls). This mirrors the pattern documented in ntfy/module.go
// Pitfall 4, but inverted: unlike ntfy (where Detect+Verify double-emit),
// budget Detect IS the full check set, so delegating Verify to Detect is correct.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-applies the configuration.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
