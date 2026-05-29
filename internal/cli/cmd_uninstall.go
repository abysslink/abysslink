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
	"log/slog"
	"os"
	"path/filepath"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/spf13/cobra"
)

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Reverse every change abysslink made, restoring files from backups (dry-run by default)",
		Example: `  # Preview what uninstall would reverse (dry-run — no changes)
  abysslink uninstall

  # Reverse all changes (restore from backups)
  abysslink uninstall --apply

  # Also remove packages and audit log (IRREVERSIBLE — extra confirm required)
  abysslink uninstall --apply --purge`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			purge, _ := cmd.Flags().GetBool("purge")

			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}
			plan, err := audit.PlanReverse(logPath)
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}

			printerInfo(p, styleBold.Render("abysslink uninstall")+"  "+styleMuted.Render("reverse all changes"))
			printerInfo(p, "")
			printReversePlan(p, plan)

			if cc.dryRun {
				printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
				if purge {
					printerInfo(p, styleMuted.Render("--purge would also remove ~/.config/abysslink and the state dir (audit log + backups)."))
				}
				return nil
			}

			ok, purgeOK, err := uninstallConfirmSeq(ctx, p, plan, purge, cc.yes)
			if err != nil {
				return err
			}
			if !ok {
				printerInfo(p, "Aborted.")
				return nil
			}

			manifest, err := audit.Reverse(logPath, false)
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}

			// When purge was confirmed, honour it; when --yes bypassed, use the
			// purge flag from the command line (already set).
			if purge && !purgeOK {
				// This branch should not happen in practice: purgeOK is always true
				// when purge=true + yes=true, and false when user declined the
				// second confirm — in which case we still run Reverse but skip purge.
				purge = false
			}

			failures := printReverseManifest(p, manifest) + removeAbysslinkDirs(p, purge)
			if failures > 0 {
				return fmt.Errorf("uninstall: %d action(s) failed", failures)
			}
			printerInfo(p, "")
			printerInfo(p, styleSuccess.Render("Uninstall complete."))
			return nil
		},
	}
	cmd.Flags().Bool("purge", false, "Also remove ~/.config/abysslink and the state dir (audit log + backups)")
	return cmd
}

// printReversePlan lists the planned reverse actions (restore/delete/skip).
func printReversePlan(p Printer, plan []audit.ReverseAction) {
	if len(plan) == 0 {
		printerInfo(p, "  No file mutations recorded in the audit log.")
		printerInfo(p, "")
		return
	}
	for _, a := range plan {
		printerInfo(p, fmt.Sprintf("  %-8s %s", a.Action, a.Target))
	}
	printerInfo(p, "")
}

// printReverseManifest prints the result of each reverse action, including the
// SHA-256 of restored content, and returns the number of failures.
func printReverseManifest(p Printer, manifest []audit.ReverseAction) int {
	failures := 0
	for _, a := range manifest {
		if a.Err != nil {
			failures++
			printerError(p, fmt.Sprintf("  %-8s %s — %v", a.Action, a.Target, a.Err))
			continue
		}
		detail := ""
		if a.Hash != "" {
			detail = styleMuted.Render("sha256:" + a.Hash[:12])
		}
		printerInfo(p, fmt.Sprintf("  %-8s %s  %s", a.Action, a.Target, detail))
	}
	printerInfo(p, "")
	return failures
}

// removeAbysslinkDirs removes the config dir (always) and, when purge is set,
// the state dir (audit log + backups). Returns the number of failures.
func removeAbysslinkDirs(p Printer, purge bool) int {
	failures := 0
	if cfgDir := abysslinkConfigDir(); cfgDir != "" {
		if err := os.RemoveAll(cfgDir); err != nil {
			printerError(p, fmt.Sprintf("  could not remove %s: %v", cfgDir, err))
			failures++
		} else {
			printerInfo(p, "  removed "+cfgDir)
		}
	}
	if !purge {
		printerInfo(p, styleMuted.Render("  Kept the state dir (audit log + backups) for forensics. Use --purge to remove it."))
		return failures
	}
	if stateDir := abysslinkStateDir(); stateDir != "" {
		if err := os.RemoveAll(stateDir); err != nil {
			printerError(p, fmt.Sprintf("  could not remove %s: %v", stateDir, err))
			failures++
		} else {
			printerInfo(p, "  removed "+stateDir+" (audit log + backups)")
		}
	}
	printerInfo(p, styleMuted.Render("  Third-party packages (tailscale, ntfy, mosh, tmux) are left installed; remove them manually if desired."))
	return failures
}

// uninstallConfirmSeq runs the two-stage confirmation sequence for uninstall --apply.
//
// Stage 1 (always): requires the user to type "UNINSTALL" (ConfirmTyped). Before the
// prompt, a blast-radius summary (count of planned actions) is printed inside a danger
// Note. With --yes the typed gate is bypassed and a slog.Warn records the skip.
//
// Stage 2 (only when purge=true): a second confirm warns that --purge will permanently
// delete the audit log + backups (irreversible). With --yes this second gate is also
// bypassed with a slog.Warn.
//
// Returns (ok, purgeOK, err): ok is false when the UNINSTALL gate is declined (caller
// must abort and not call audit.Reverse). purgeOK is true only when purge=true AND the
// user confirmed the second gate (or --yes was set).
func uninstallConfirmSeq(ctx context.Context, p Printer, plan []audit.ReverseAction, purge, yes bool) (bool, bool, error) {
	// Print blast-radius summary so the user sees the full scope before the prompt.
	nActions := len(plan)
	restores, deletes := 0, 0
	for _, a := range plan {
		switch a.Action {
		case "restore":
			restores++
		case "delete":
			deletes++
		}
	}
	printerInfo(p, fmt.Sprintf(
		"  Blast radius: %d file(s) affected (%d restore, %d delete).",
		nActions, restores, deletes))
	printerInfo(p, "")

	if yes {
		slog.Warn("uninstall --yes: skipping UNINSTALL typed confirmation gate; executing immediately")
	} else if !interactive(false, false) {
		// Non-interactive context (CI, pipe, no TTY): abort without hanging.
		return false, false, nil
	}

	// Stage 1: typed UNINSTALL confirm.
	ok, err := tui.ConfirmTyped(ctx,
		"Type UNINSTALL to reverse every change made by abysslink",
		"UNINSTALL",
		yes)
	if err != nil {
		return false, false, err
	}
	if !ok {
		return false, false, nil
	}

	// Stage 2: purge extra confirm.
	if !purge {
		return true, false, nil
	}

	printerInfo(p, "")
	printerInfo(p, styleWarn.Render("  WARNING: --purge will permanently delete the audit log and all backups."))
	printerInfo(p, styleWarn.Render("  This is NOT reversible. There will be no record of changes after this."))
	printerInfo(p, "")

	if yes {
		slog.Warn("uninstall --yes: skipping --purge irreversibility confirmation gate")
		return true, true, nil
	}

	purgeOK, err := tui.Confirm(ctx,
		"--purge permanently deletes the audit log + backups. Proceed?",
		yes)
	if err != nil {
		return true, false, err
	}
	return true, purgeOK, nil
}

// abysslinkConfigDir returns the XDG config dir for abysslink (~/.config/abysslink).
func abysslinkConfigDir() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "abysslink")
}

// abysslinkStateDir returns the XDG state dir for abysslink (~/.local/state/abysslink).
func abysslinkStateDir() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "abysslink")
}
