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

package lock

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// lockStatus is the subset of `tailscale lock status --json` we need.
type lockStatus struct {
	Enabled bool `json:"Enabled"`
}

// Module implements the lock module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the module name.
func (m *Module) Name() string { return "lock" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect checks the Tailnet Lock state.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "tailscale", "lock", "status", "--json")
	if err != nil {
		return findings, fmt.Errorf("lock detect: run tailscale lock status: %w", err)
	}

	if res.ExitCode != 0 {
		slog.Warn("lock detect: tailscale lock status returned non-zero", "stderr", res.Stderr)
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "lock_status",
			Severity: modules.SeverityWarning,
			Message:  "could not query Tailnet Lock status; tailscale may not be running",
		})
		return findings, nil
	}

	var status lockStatus
	if err := json.Unmarshal([]byte(res.Stdout), &status); err != nil {
		return findings, fmt.Errorf("lock detect: parse lock status JSON: %w", err)
	}

	slog.Debug("lock detect", "lock_enabled", status.Enabled, "cfg_enabled", m.cfg.Tailnet.Lock.Enabled)

	if m.cfg.Tailnet.Lock.Enabled && !status.Enabled {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "lock_enabled",
			Severity: modules.SeverityWarning,
			Message:  "config requires Tailnet Lock but it is not enabled on this tailnet",
		})
	} else if status.Enabled {
		// Emit explicit OK so "check ran and passed" is distinguishable from
		// "check never ran" in the threat-model tri-state (D-03 / DOC-01).
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "lock_enabled",
			Severity: modules.SeverityOK,
			Message:  "lock_enabled: Tailnet Lock is enabled on this tailnet",
		})
	}

	return findings, nil
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		if f.Severity == modules.SeverityOK {
			continue // OK findings represent passing checks; no action needed
		}
		if f.Check == "lock_enabled" {
			actions = append(actions, modules.Action{
				Module: m.Name(),
				Description: "ACTION REQUIRED: run `tailscale lock init` to enable Tailnet Lock " +
					"— copy the disablement secrets before closing the terminal",
				Explain: "Tailnet Lock cryptographically signs every device that joins your tailnet. " +
					"Initialization prints disablement secrets that are the ONLY way to turn lock off later — " +
					"store them in a password manager and on paper before closing the terminal.",
				Reversible: false,
			})
		}
	}

	return actions, nil
}

// Apply does not auto-initialize Tailnet Lock: initialization prints disablement
// secrets that the user MUST record before closing the terminal. That interactive
// requirement is beyond what a module Apply can own safely.
//
// Instead it returns a clear, actionable error so the apply run surfaces the
// manual step rather than silently claiming success.
func (m *Module) Apply(ctx context.Context) error {
	findings, err := m.Detect(ctx)
	if err != nil {
		return err
	}
	for _, f := range findings {
		if f.Severity == modules.SeverityOK {
			continue // OK findings represent passing checks; no action needed
		}
		if f.Check == "lock_enabled" {
			return fmt.Errorf(
				"lock: Tailnet Lock is required but not yet enabled.\n\n" +
					"  Enable it now:\n" +
					"    tailscale lock init\n\n" +
					"  IMPORTANT: the command prints disablement secrets — the ONLY way to\n" +
					"  turn lock off later. Save them in your password manager AND on paper\n" +
					"  before closing the terminal. Once the window is closed they cannot be\n" +
					"  recovered.\n\n" +
					"  After init, re-run: abysslink up --apply",
			)
		}
	}
	return nil
}

// Verify is a no-op for the lock module — all checks run in Detect.
// Pitfall 4: do NOT call Detect here — runner.Doctor calls both Detect and Verify;
// re-running Detect would produce duplicate lock_enabled findings per doctor pass.
// lock is report-only (Apply handles actual remediation); Verify adds no new
// information beyond Detect; returning nil avoids double-emission.
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
