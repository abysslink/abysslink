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
	"log/slog"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/spf13/cobra"
)

func newUpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Converge the system to match abysslink.yaml (dry-run by default)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			// Header.
			if cc.dryRun {
				header := styleBold.Render("abysslink up") + "  " + styleMuted.Render("dry-run · preview only")
				printerInfo(p, styleHeaderBox.Render(header))
			} else {
				header := styleBold.Render("abysslink up") + "  " + styleSuccess.Render("✦  applying")
				printerInfo(p, styleHeaderBox.Render(header))
			}
			printerInfo(p, "")

			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}
			mods := allModules(deps)
			r, err := modules.NewRunner(mods, cc.cfg)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			// Pass 1 — Scan phase (always runs).
			printerInfo(p, "  "+iconSpinStr()+"  "+styleMuted.Render(fmt.Sprintf("Scanning %d modules...", len(mods))))

			actions, findings, planErr := r.PlanAll(ctx, func(evt modules.ModuleEvent) {
				printerInfo(p, scanRowStr(evt))
			})
			if planErr != nil {
				return fmt.Errorf("up: %w", planErr)
			}

			printPlanDetail(p, actions, findings, cc.dryRun)

			// Fail-closed gates run only at apply time (dry-run still previews).
			if !cc.dryRun {
				// SSH re-auth interval may not be raised above the 12h default
				// without explicit operator consent.
				accept, _ := cmd.Flags().GetBool("accept-checkperiod-extension")
				if err := checkPeriodGate(cc.cfg, accept); err != nil {
					return err
				}
			}

			// Fail-closed gate: never configure remote access on an unencrypted
			// disk. Blocks apply unless the operator explicitly overrides.
			if !cc.dryRun {
				if blockers := diskEncryptionBlockers(findings); len(blockers) > 0 {
					forceUnsafe, _ := cmd.Flags().GetBool("force-unsafe")
					if !forceUnsafe {
						for _, b := range blockers {
							printerError(p, "  ✗  "+b.Message)
						}
						return fmt.Errorf("up: refusing to apply — full-disk encryption is required (fail-closed); enable it, or re-run with --force-unsafe to override (NOT recommended)")
					}
					slog.Warn("up: --force-unsafe set — applying despite disk encryption being disabled; remote access on an unencrypted disk is dangerous")
				}
			}

			// Pass 2 — Apply phase (only if not dry-run).
			var applyFindings []modules.Finding
			var applyErr error
			if !cc.dryRun {
				unique := uniqueActions(actions)
				printerInfo(p, "  "+styleMuted.Render(strings.Repeat("─", 48)))
				printerInfo(p, "  "+styleBold.Render(fmt.Sprintf("Applying %d changes...", len(unique))))
				printerInfo(p, "")

				start := time.Now()
				applyFindings, applyErr = r.ApplyAll(ctx, func(evt modules.ModuleEvent) {
					printerInfo(p, applyRowStr(evt))
				})
				printFinalSummary(p, actions, applyFindings, time.Since(start))
			}

			// Pass 3 — Next steps (always runs).
			allFindings := append(findings, applyFindings...)
			printNextSteps(p, allFindings)

			if applyErr != nil {
				return fmt.Errorf("up: %w", applyErr)
			}
			return nil
		},
	}
	cmd.Flags().Bool("force-unsafe", false,
		"Override fail-closed safety checks such as disk encryption (DANGEROUS)")
	cmd.Flags().Bool("accept-checkperiod-extension", false,
		"Allow ssh_check_period to exceed the 12h re-auth default")
	return cmd
}

// checkPeriodGate enforces the immutable default that the SSH re-auth interval
// is never raised above 12h without explicit consent. Values at or below 12h
// (settable down) always pass.
func checkPeriodGate(cfg *config.Config, accept bool) error {
	d, err := time.ParseDuration(cfg.Mobile.SSHCheckPeriod)
	if err != nil {
		return nil // malformed durations are caught by config.Validate
	}
	if d > 12*time.Hour && !accept {
		return fmt.Errorf("up: ssh_check_period %s exceeds the 12h security default; "+
			"re-run with --accept-checkperiod-extension to allow a longer re-auth interval",
			cfg.Mobile.SSHCheckPeriod)
	}
	return nil
}

// diskEncryptionBlockers returns the subset of findings that must fail closed:
// fatal disk-encryption checks (FileVault on macOS, LUKS on Linux). abysslink
// up refuses to configure remote access on an unencrypted disk unless the user
// explicitly passes --force-unsafe. Note this deliberately does NOT block on
// other fatals such as "tool not installed" — up exists to fix those.
func diskEncryptionBlockers(findings []modules.Finding) []modules.Finding {
	var out []modules.Finding
	for _, f := range findings {
		if f.Module == "hardening" && f.Severity == modules.SeverityFatal &&
			(f.Check == "filevault" || f.Check == "luks") {
			out = append(out, f)
		}
	}
	return out
}

// printNextSteps prints a styled box for findings that require manual action.
func printNextSteps(p Printer, findings []modules.Finding) {
	type step struct {
		title string
		lines []string
	}
	var steps []step
	seen := map[string]bool{}

	for _, f := range findings {
		if seen[f.Check] {
			continue
		}
		seen[f.Check] = true

		switch f.Check {
		case "needs_login":
			steps = append(steps, step{
				title: styleWarn.Render("Tailscale needs authentication"),
				lines: []string{
					"Run:",
					"  " + styleCode.Render("tailscale login"),
					"",
					"A browser will open. Authenticate, then come back and run:",
					"  " + styleCode.Render("abysslink up --apply"),
				},
			})
		case "ssh_sandboxed":
			steps = append(steps, step{
				title: styleWarn.Render("Tailscale SSH requires the CLI build"),
				lines: []string{
					"The App Store / GUI version of Tailscale is sandboxed and",
					"cannot run the SSH server. Install the CLI version:",
					"  " + styleCode.Render("brew install tailscale"),
					"",
					"Then re-run:",
					"  " + styleCode.Render("abysslink up --apply"),
				},
			})
		}

		if strings.Contains(f.Module, "tailscale") && f.Check == "installed" {
			steps = append(steps, step{
				title: styleWarn.Render("Tailscale is not installed"),
				lines: []string{
					"Install from: " + styleCode.Render("https://tailscale.com/download"),
					"Then re-run: " + styleCode.Render("abysslink up --apply"),
				},
			})
		}
	}

	if len(steps) == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString(styleBold.Render("Next steps") + "\n\n")
	for i, s := range steps {
		sb.WriteString(s.title + "\n\n")
		for _, l := range s.lines {
			sb.WriteString(l + "\n")
		}
		if i < len(steps)-1 {
			sb.WriteString("\n" + styleMuted.Render(strings.Repeat("─", 48)) + "\n\n")
		}
	}

	printerInfo(p, styleNextStepBox.Render(strings.TrimRight(sb.String(), "\n")))
	printerInfo(p, "")
}
