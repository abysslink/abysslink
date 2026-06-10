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

package power

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the power module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the module name.
func (m *Module) Name() string { return "power" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{} }

// Detect checks the current power management settings.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	switch runtime.GOOS {
	case "darwin":
		findings = append(findings, m.detectDarwin(ctx)...)
	case "linux":
		// Linux power management is handled differently (e.g., systemd inhibit).
		slog.Debug("power detect: Linux power management not yet implemented")
	default:
		slog.Warn("power detect: unsupported OS", "os", runtime.GOOS)
	}

	return findings, nil
}

// detectDarwin uses pmset to inspect sleep settings.
func (m *Module) detectDarwin(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	// Read the AC (custom) profile explicitly so the read agrees with the
	// write target (`pmset -c …`). Bare `pmset -g` reports the *active* power
	// source, which on battery is the wrong profile (CR-01).
	res, err := m.runner.Run(ctx, "pmset", "-g", "custom")
	if err != nil || res.ExitCode != 0 {
		slog.Warn("power detect: pmset failed", "error", err)
		return findings
	}

	output := res.Stdout
	slog.Debug("power detect darwin", "pmset_output", output)

	// When closed_lid_ac = keep-awake, we need sleep = 0 (never) while on AC.
	if m.cfg.Power.ClosedLidAC == "keep-awake" {
		state, found := acSleepState(output)
		// Warn when sleep is positively parsed as enabled (non-zero). Unknown
		// output (found == false) is not flagged here — Detect is advisory and
		// a parse failure should not produce a spurious warning; the apply path
		// (WR-02) errs toward running the fix on unknown state instead.
		if found && state != 0 {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "sleep_disabled",
				Severity: modules.SeverityWarning,
				Message:  "pmset sleep is not 0 — system may sleep while on AC. abysslink only auto-fixes this when `power.closed_lid_ac: keep-awake` is set in abysslink.yaml; otherwise enable manually: sudo pmset -c sleep 0 disksleep 0",
			})
		}
	}

	return findings
}

// acSleepState parses the AC-profile sleep value from `pmset -g custom` output.
// It returns (value, true) when a `sleep` line is positively parsed for the AC
// power source, and (0, false) when no AC sleep value can be determined (empty
// output, parse failure, or unexpected pmset format).
//
// `pmset -g custom` emits two blocks headed by "AC Power:" and "Battery Power:".
// Only the AC block is consulted so a non-zero battery sleep value is never
// mistaken for AC (CR-01). When no power-source header is present (e.g. legacy
// `pmset -g` output or a test fixture), every sleep line is considered so the
// parser degrades gracefully.
func acSleepState(output string) (int, bool) {
	inAC := true // default: no header seen yet → treat all lines as in-scope
	sawHeader := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "AC Power"):
			inAC, sawHeader = true, true
			continue
		case strings.HasPrefix(line, "Battery Power"):
			inAC, sawHeader = false, true
			continue
		}
		if sawHeader && !inAC {
			continue
		}
		if !strings.HasPrefix(line, "sleep") {
			continue
		}
		parts := strings.Fields(line)
		// Lines look like "sleep 10" or "sleep  0 (sleep prevented by powerd)".
		if len(parts) >= 2 && parts[0] == "sleep" {
			if v, err := strconv.Atoi(parts[1]); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for range findings {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "configure sleep settings via pmset",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply executes planned changes.
func (m *Module) Apply(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		return m.applyDarwin(ctx)
	case "linux":
		slog.Info("power apply: Linux — no automatic power changes; configure systemd-inhibit manually")
		return nil
	default:
		return nil
	}
}

// applyDarwin applies macOS sleep settings via pmset.
func (m *Module) applyDarwin(ctx context.Context) error {
	if m.cfg.Power.ClosedLidAC != "keep-awake" {
		return nil
	}

	// Short-circuit: probe the AC sleep state before invoking sudo. When init
	// already ran maybeFixSleep (via runSecurityFixes), sleep is already 0 —
	// re-running sudo pmset would prompt for a password unnecessarily. Read the
	// AC (custom) profile so the probe agrees with the `pmset -c` write target
	// (CR-01). Only short-circuit on a positively-parsed `sleep 0`; on unknown
	// output (parse failure / unexpected format) fall through to the fix rather
	// than assuming sleep is already disabled (WR-02).
	if res, err := m.runner.Run(ctx, "pmset", "-g", "custom"); err == nil && res.ExitCode == 0 {
		if state, found := acSleepState(res.Stdout); found && state == 0 {
			slog.Debug("power apply: sleep already disabled — skipping pmset")
			return nil
		}
	}

	slog.Info("power apply: setting pmset -c sleep 0 disksleep 0")
	// RunInteractive lets sudo reach the real tty so macOS's tty-keyed credential
	// cache is reusable across privileged calls within the same init session.
	if err := m.runner.RunInteractive(ctx, "sudo", "pmset", "-c", "sleep", "0", "disksleep", "0"); err != nil {
		return fmt.Errorf("power apply: pmset: %w", err)
	}
	return nil
}

// Verify is a no-op for the power module — all checks run in Detect.
// Pitfall 4 (Doctor double-emission): do NOT call Detect here — runner.Doctor
// calls both Detect and Verify, so re-running Detect would double-emit every
// Detect finding per doctor pass (W4/NET-18). Verify adds no new information
// beyond Detect; returning nil avoids the duplication (mirrors ssh/ntfy).
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
