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
	"context"
	"fmt"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/spf13/cobra"
)

func newRepairCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repair",
		Short: "Auto-fix failures detected by doctor",
		Example: `  # Preview what repair would fix (dry-run — no changes)
  abysslink repair

  # Apply all auto-fixable issues
  abysslink repair --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			if !cc.jsonOut {
				mode := styleMuted.Render("repair drift")
				if cc.dryRun {
					mode = styleWarn.Render("preview only — run with --apply to make changes")
				}
				commandHeader(p, "repair", mode)
			}

			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("repair: %w", err)
			}
			mods := allModules(deps)
			r, err := modules.NewRunner(mods, cc.cfg)
			if err != nil {
				return fmt.Errorf("repair: %w", err)
			}

			// Run doctor to find all current findings.
			findings, err := r.Doctor(ctx)
			if err != nil {
				return fmt.Errorf("repair: doctor: %w", err)
			}

			if len(findings) == 0 {
				printerInfo(p, "No issues found — system is healthy.")
				return nil
			}

			// Collect modules with non-OK findings.
			needsRepair := map[string]bool{}
			for _, f := range findings {
				if f.Severity != modules.SeverityOK {
					needsRepair[f.Module] = true
				}
			}

			if len(needsRepair) == 0 {
				printerInfo(p, "All checks passed — nothing to repair.")
				return nil
			}

			repairErrs, gateErr := runRepairApply(ctx, cmd, p, cc, mods, needsRepair, findings)
			if gateErr != nil {
				// A fail-closed apply gate refused (e.g. Tailnet Lock off) — return
				// immediately (exit 2). No module Repair ran, so nothing to flush.
				return gateErr
			}

			// F-59: replay manual steps deferred during Repair (e.g. acl manual
			// mode) after all repairs ran — even when some modules failed, the
			// successfully-collected steps must still reach the user.
			if err := flushManualSteps(ctx, cc, p); err != nil {
				return fmt.Errorf("repair: manual steps: %w", err)
			}

			if len(repairErrs) > 0 {
				return fmt.Errorf("repair: %d module(s) failed to repair", len(repairErrs))
			}

			return nil
		},
	}
	// Repair re-runs module bring-up — including the tailscale/ssh modules whose
	// Repair == Apply shells `tailscale up` / `tailscale set --ssh` — so the
	// --apply path is subject to the SAME fail-closed apply gates as `up`. Expose
	// the same audited override flags so a legitimately lock-off / at-risk rig can
	// still be repaired with explicit, recorded consent (LOCK-REPAIR-01).
	cmd.Flags().Bool("force-unsafe", false,
		"Override fail-closed safety checks such as disk encryption (DANGEROUS)")
	cmd.Flags().Bool("accept-checkperiod-extension", false,
		"Allow ssh_check_period to exceed the 12h re-auth default")
	cmd.Flags().Bool("accept-lock-disabled", false,
		"Proceed with `repair --apply` even though Tailnet Lock is not enabled (NOT recommended; this choice is audited)")
	return cmd
}

// runRepairApply runs the fail-closed apply-time gates and then the per-module
// repairs. On the --apply path (`!cc.dryRun`) it runs the SAME gates as `up`
// (tailscaled reachability, the 12h checkPeriod ceiling, disk encryption, and
// the LIVE Tailnet Lock hard gate) BEFORE any module Repair executes — repair
// re-runs the tailscale/ssh module bring-up (`tailscale set --ssh`), so it must
// not re-establish phone→laptop remote access on a lock-off tailnet without the
// explicit, audited --accept-lock-disabled override (LOCK-REPAIR-01 / BKLG-01).
// The gates read LIVE state (never config), so a `backend.type: headscale`
// intent cannot make them skippable. In dry-run mode the gates are skipped —
// dry-run mutates nothing, so there is nothing to gate.
//
// Returns the per-module repair errors and, separately, a fatal gate error to
// surface immediately (exit 2) without attempting any repair.
func runRepairApply(ctx context.Context, cmd *cobra.Command, p Printer, cc *cmdContext, mods []modules.Module, needsRepair map[string]bool, findings []modules.Finding) (repairErrs []error, gateErr error) {
	if !cc.dryRun {
		if err := applyTimeGates(cmd, p, cc, findings); err != nil {
			// Fail-closed gates are the documented "2 — Fatal" exit class (W2); a
			// plain error would otherwise map to exit 1.
			return nil, &exitError{code: exitCodeFatal, err: err}
		}
	}
	return runModuleRepairs(ctx, p, mods, needsRepair, cc.dryRun, cc.jsonOut), nil
}

// runModuleRepairs calls Repair on each module flagged in needsRepair, printing
// progress. In dry-run mode it reports what it would repair without mutating.
// It returns the errors from any modules that failed to repair.
func runModuleRepairs(ctx context.Context, p Printer, mods []modules.Module, needsRepair map[string]bool, dryRun, jsonOut bool) []error {
	modMap := make(map[string]modules.Module, len(mods))
	for _, m := range mods {
		modMap[m.Name()] = m
	}

	var repairErrs []error
	for modName := range needsRepair {
		m, ok := modMap[modName]
		if !ok {
			continue
		}

		// Dry-run prints ONLY the [plan] line — "Repairing module:" would
		// falsely imply a mutation is happening (CLI-29). The decorative progress
		// is human-only: under --json it is suppressed so no {"msg"} glyph/prose
		// leaks into the machine stream (repair has no structured json output;
		// failures are still returned via repairErrs and surfaced by the exit code).
		if dryRun {
			if !jsonOut {
				printerInfo(p, fmt.Sprintf("  [plan] would repair: %s", modName))
			}
			continue
		}
		// NOTE: m.Repair drives RunInteractive (sudo TTY passthrough) for the
		// power/tailscale modules, so it must NOT run under a Bubble Tea spinner —
		// that would suppress the password prompt and hang. Keep the static line;
		// only the glyph/colour is branded.
		if !jsonOut {
			printerInfo(p, "  "+iconSpinStr()+"  "+styleMuted.Render("Repairing module: "+modName))
		}
		if repErr := m.Repair(ctx); repErr != nil {
			if !jsonOut {
				printerError(p, "  "+iconFatalStr()+"  "+styleFatal.Render(fmt.Sprintf("repair [%s]: %v", modName, repErr)))
			}
			repairErrs = append(repairErrs, repErr)
			continue
		}
		if !jsonOut {
			printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("Repaired: "+modName))
		}
	}
	return repairErrs
}
