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

package cli

import (
	"fmt"
	"strings"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/spf13/cobra"
)

func newUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Converge the system to match abysslink.yaml (dry-run by default)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			if cc.dryRun {
				printerInfo(p, "")
				printerInfo(p, "  abysslink up  (dry-run — no changes made)")
				printerInfo(p, "  To apply:  abysslink up --apply")
				printerInfo(p, "")
			} else {
				printerInfo(p, "")
				printerInfo(p, "  abysslink up --apply")
				printerInfo(p, "")
			}

			mods := allModules(cc.runner, cc.cfg)
			r, err := modules.NewRunner(mods, cc.cfg)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			actions, findings, err := r.Up(ctx, cc.dryRun)

			// Print what was planned / applied.
			printUpSummary(p, actions, findings, cc.dryRun)

			// Print next-step guidance extracted from findings.
			printNextSteps(p, findings)

			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			return nil
		},
	}
}

// printUpSummary renders a human-readable summary of actions and findings.
func printUpSummary(p Printer, actions []modules.Action, findings []modules.Finding, dryRun bool) {
	if len(actions) == 0 {
		printerInfo(p, "  ✓  System is already converged — nothing to do.")
		printerInfo(p, "")
		return
	}

	// Group actions by module for compact display.
	seen := map[string]bool{}
	for _, a := range actions {
		key := a.Module + "|" + a.Description
		if seen[key] {
			continue
		}
		seen[key] = true

		var icon, verb string
		if dryRun {
			icon = "→"
			verb = "will"
		} else {
			// Check if a finding blocks this module (e.g. needs_login).
			blocked := false
			for _, f := range findings {
				if f.Module == a.Module && (f.Check == "needs_login" || f.Check == "ssh_sandboxed") {
					blocked = true
					break
				}
			}
			if blocked {
				icon = "⚠"
				verb = "skipped —"
			} else {
				icon = "✓"
				verb = "done —"
			}
		}
		printerInfo(p, fmt.Sprintf("  %s  [%s]  %s %s", icon, a.Module, verb, a.Description))
	}
	printerInfo(p, "")

	// Warnings and fatals from findings (deduplicated).
	seenMsg := map[string]bool{}
	for _, f := range findings {
		key := f.Module + "|" + f.Check
		if seenMsg[key] {
			continue
		}
		seenMsg[key] = true
		switch f.Severity {
		case modules.SeverityFatal:
			printerError(p, fmt.Sprintf("  ✕  FATAL [%s] %s", f.Module, f.Message))
		case modules.SeverityWarning:
			if !isNextStepFinding(f) {
				printerWarn(p, fmt.Sprintf("  ⚠  WARN  [%s] %s", f.Module, f.Message))
			}
		}
	}
}

// printNextSteps prints a "Next steps" block for findings that require manual action.
func printNextSteps(p Printer, findings []modules.Finding) {
	var steps []string
	seen := map[string]bool{}

	for _, f := range findings {
		if seen[f.Check] {
			continue
		}
		seen[f.Check] = true

		switch f.Check {
		case "needs_login":
			steps = append(steps,
				"1. Log in to Tailscale:",
				"      tailscale login",
				"   (Opens a browser — authenticate, then return to the terminal.)",
				"",
				"2. Re-run:",
				"      abysslink up --apply",
			)
		case "ssh_sandboxed":
			steps = append(steps,
				"• Tailscale SSH requires the CLI build (not the App Store version).",
				"  Install it:",
				"      brew install tailscale",
				"  Then re-run:",
				"      abysslink up --apply",
			)
		case "installed":
			if strings.Contains(f.Module, "tailscale") {
				steps = append(steps,
					"• Tailscale is not installed. Install from: https://tailscale.com/download",
				)
			}
		}
	}

	if len(steps) == 0 {
		return
	}

	printerInfo(p, "  ┌─ Next steps ────────────────────────────────────────┐")
	for _, s := range steps {
		printerInfo(p, "  │  "+s)
	}
	printerInfo(p, "  └────────────────────────────────────────────────────┘")
	printerInfo(p, "")
}

// isNextStepFinding returns true for findings handled by printNextSteps
// (so they're not double-printed in the warnings block).
func isNextStepFinding(f modules.Finding) bool {
	switch f.Check {
	case "needs_login", "ssh_sandboxed":
		return true
	}
	return false
}
