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
	"time"

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

			// Header.
			if cc.dryRun {
				header := styleBold.Render("abysslink up") + "  " + styleMuted.Render("dry-run · preview only")
				printerInfo(p, styleHeaderBox.Render(header))
			} else {
				header := styleBold.Render("abysslink up") + "  " + styleSuccess.Render("✦  applying")
				printerInfo(p, styleHeaderBox.Render(header))
			}
			printerInfo(p, "")

			mods := allModules(cc.runner, cc.cfg)
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
