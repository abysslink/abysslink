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
	"os"
	"path/filepath"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/spf13/cobra"
)

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Reverse every change abysslink made, restoring files from backups (dry-run by default)",
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

			ok, err := confirmAction(ctx, cc, "Reverse all changes above and remove abysslink configuration?")
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
