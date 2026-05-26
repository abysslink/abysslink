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

			// Header.
			if cc.dryRun {
				header := styleBold.Render("abysslink up") + "  " + styleMuted.Render("dry-run · no changes made")
				printerInfo(p, styleHeaderBox.Render(header))
				printerInfo(p, styleMuted.Render("  Run with --apply to apply changes.")+"\n")
			} else {
				header := styleBold.Render("abysslink up") + "  " + styleSuccess.Render("applying")
				printerInfo(p, styleHeaderBox.Render(header))
				printerInfo(p, "")
			}

			mods := allModules(cc.runner, cc.cfg)
			r, err := modules.NewRunner(mods, cc.cfg)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			actions, findings, runErr := r.Up(ctx, cc.dryRun)

			printUpTable(p, actions, findings, cc.dryRun)
			printNextSteps(p, findings)

			if runErr != nil {
				return fmt.Errorf("up: %w", runErr)
			}
			return nil
		},
	}
}

// printUpTable renders per-module status rows.
func printUpTable(p Printer, actions []modules.Action, findings []modules.Finding, dryRun bool) {
	if len(actions) == 0 {
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("System is already converged — nothing to do."))
		printerInfo(p, "")
		return
	}

	// Build a set of blocked modules (needs_login, sandboxed, etc.).
	blocked := map[string]string{} // module → reason
	for _, f := range findings {
		switch f.Check {
		case "needs_login":
			blocked[f.Module] = "authentication required"
		case "ssh_sandboxed":
			blocked[f.Module] = "GUI build — Tailscale SSH unavailable"
		case "installed":
			blocked[f.Module] = "not installed — manual step required"
		}
	}

	// Deduplicate actions per module.
	seenModules := map[string]bool{}
	seenDescriptions := map[string]bool{}
	for _, a := range actions {
		key := a.Module + "|" + a.Description
		if seenDescriptions[key] {
			continue
		}
		seenDescriptions[key] = true

		mod := styleBold.Render(fmt.Sprintf("%-16s", a.Module))

		if dryRun {
			desc := styleMuted.Render(a.Description)
			printerInfo(p, fmt.Sprintf("  %s  %s  %s", iconArrowStr(), mod, desc))
		} else if reason, isBlocked := blocked[a.Module]; isBlocked {
			if !seenModules[a.Module] {
				seenModules[a.Module] = true
				printerInfo(p, fmt.Sprintf("  %s  %s  %s",
					iconWarnStr(), mod, styleWarn.Render(reason)))
			}
		} else {
			desc := styleSuccess.Render(a.Description)
			printerInfo(p, fmt.Sprintf("  %s  %s  %s", iconDoneStr(), mod, desc))
		}
	}
	printerInfo(p, "")

	// Extra warnings (non-next-step).
	seenMsg := map[string]bool{}
	for _, f := range findings {
		key := f.Module + "|" + f.Check
		if seenMsg[key] || isNextStepFinding(f) {
			continue
		}
		seenMsg[key] = true
		switch f.Severity {
		case modules.SeverityFatal:
			printerInfo(p, fmt.Sprintf("  %s  %s  %s",
				iconFatalStr(),
				styleBold.Render(fmt.Sprintf("%-16s", f.Module)),
				styleFatal.Render(f.Message)))
		case modules.SeverityWarning:
			printerInfo(p, fmt.Sprintf("  %s  %s  %s",
				iconWarnStr(),
				styleBold.Render(fmt.Sprintf("%-16s", f.Module)),
				styleWarn.Render(f.Message)))
		}
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

// isNextStepFinding returns true for findings rendered in the next-steps box.
func isNextStepFinding(f modules.Finding) bool {
	switch f.Check {
	case "needs_login", "ssh_sandboxed":
		return true
	}
	return false
}
