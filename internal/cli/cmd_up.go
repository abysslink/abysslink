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
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

func newUpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Converge the system to match abysslink.yaml (dry-run by default)",
		Example: `  # Preview what up would do (dry-run by default — no changes)
  abysslink up

  # Apply all changes (converge the system)
  abysslink up --apply

  # Show per-action rationale alongside each planned change
  abysslink up --explain`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			// Header.
			if cc.dryRun {
				header := styleBold.Render("abysslink up") + "  " + styleWarn.Render("preview only — run with --apply to make changes")
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
			actions, findings, planErr := runScan(ctx, p, r, mods, cc)
			if planErr != nil {
				return fmt.Errorf("up: %w", planErr)
			}

			printPlanDetail(p, actions, findings, cc.dryRun, cc.explain)

			// All fail-closed gates in one block to keep cyclomatic complexity low.
			if !cc.dryRun {
				if err := applyTimeGates(cmd, p, cc, findings); err != nil {
					return err
				}
			}

			// Pass 2 — Apply phase (only if not dry-run).
			var applyFindings []modules.Finding
			var applyErr error
			var applyElapsed time.Duration
			if !cc.dryRun {
				applyFindings, applyElapsed, applyErr = runApply(ctx, cmd, p, r, actions, cc)
				printFinalSummary(p, actions, applyFindings, applyElapsed)
			}

			// Pass 3 — Next steps + success summary (always runs).
			allFindings := append(findings, applyFindings...)
			printNextSteps(p, allFindings, cc.cfg)
			if !cc.dryRun && applyErr == nil {
				printSuccessSummary(p, cc.cfg)
			}

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

// runScan runs the Plan phase for all modules, choosing between an animated live
// table (TTY, color enabled, not JSON) and the plain printer callback path.
// Returns the combined actions, findings, and first error.
func runScan(ctx context.Context, p Printer, r *modules.Runner, mods []modules.Module, cc *cmdContext) ([]modules.Action, []modules.Finding, error) {
	animate := animationEnabled(cc.jsonOut)

	if animate {
		return runScanAnimated(ctx, p, r, mods)
	}

	// Plain path — emit rows via Printer as events arrive.
	printerInfo(p, "  "+iconSpinStr()+"  "+styleMuted.Render(fmt.Sprintf("Scanning %d modules...", len(mods))))
	return r.PlanAll(ctx, func(evt modules.ModuleEvent) {
		printerInfo(p, scanRowStr(evt))
	})
}

// runScanAnimated drives a live tui.LiveTable for the scan phase.
func runScanAnimated(ctx context.Context, _ Printer, r *modules.Runner, _ []modules.Module) ([]modules.Action, []modules.Finding, error) {
	table := tui.NewLiveTable()
	resultCh := make(chan struct {
		actions  []modules.Action
		findings []modules.Finding
		err      error
	}, 1)

	go func() {
		actions, findings, err := r.PlanAll(ctx, func(evt modules.ModuleEvent) {
			table.SendRow(tui.RowEvent{
				Module:  evt.Module,
				Index:   evt.Index,
				Total:   evt.Total,
				HasWarn: hasFindingSeverity(evt.Findings, modules.SeverityWarning),
				WarnMsg: firstFindingMessage(evt.Findings, nil),
			})
		})
		table.Done(err)
		resultCh <- struct {
			actions  []modules.Action
			findings []modules.Finding
			err      error
		}{actions, findings, err}
	}()

	if _, err := runTableProgram(table); err != nil {
		return nil, nil, err
	}

	res := <-resultCh
	return res.actions, res.findings, res.err
}

// applyAnimationEnabled decides whether the apply phase may use the live
// Bubble Tea table. Animation is disabled — independent of TTY/color/jsonOut
// — when ANY planned action requires sudo. Rationale: tea.NewProgram in
// internal/tui.RunLiveTable owns os.Stdin while running. If apply spawns an
// interactive child (sudo password prompt via shell.ExecRunner.RunInteractive,
// which also wires cmd.Stdin = os.Stdin), the two race for stdin bytes, the
// password reads garbage, sudo fails, and Ctrl-C is swallowed by the tea
// event loop. Falling back to the plain Printer-callback path returns stdin
// ownership to the child process so sudo can read the password normally.
// Scan-phase animation is unaffected — there is no sudo on the scan path.
func applyAnimationEnabled(jsonOut bool, sudoLines []string) bool {
	if len(sudoLines) > 0 {
		return false
	}
	return animationEnabled(jsonOut)
}

// runApply runs the Apply phase, wrapping with a ConfirmBlast gate and choosing
// between animated and plain output paths. Returns findings, elapsed time, and error.
// If the user aborts via ConfirmBlast, findings and elapsed are zero and error is nil.
func runApply(ctx context.Context, cmd *cobra.Command, p Printer, r *modules.Runner, actions []modules.Action, cc *cmdContext) ([]modules.Finding, time.Duration, error) {
	unique := uniqueActions(actions)
	sudoLines := sudoActionsFromActions(unique)

	// Build a summary string for ConfirmBlast.
	var sb strings.Builder
	if len(sudoLines) > 0 {
		sb.WriteString("sudo required for:\n")
		for _, l := range sudoLines {
			sb.WriteString("  " + l + "\n")
		}
	}
	summary := strings.TrimRight(sb.String(), "\n")

	// ConfirmBlast — the last gate before mutation (after fail-closed gates).
	// Skipped when cc.yes=true (ConfirmBlast handles that internally).
	// Never reached in dry-run (caller guards).
	ok, err := tui.ConfirmBlast(cmd.Context(), summary, len(unique), cc.yes)
	if err != nil {
		return nil, 0, fmt.Errorf("up: confirm: %w", err)
	}
	if !ok {
		printerInfo(p, "  Aborted.")
		return nil, 0, nil
	}

	// Proceed with apply.
	printSudoNotice(p, unique)
	printerInfo(p, "  "+styleMuted.Render(strings.Repeat("─", 48)))
	printerInfo(p, "  "+styleBold.Render(fmt.Sprintf("Applying %d changes...", len(unique))))
	printerInfo(p, "")

	// Animation is force-disabled when any module requires sudo so the tea
	// program does not race with the password prompt for stdin. See
	// applyAnimationEnabled for the full rationale.
	animate := applyAnimationEnabled(cc.jsonOut, sudoLines)
	if animate {
		findings, applyErr := runApplyAnimated(ctx, r)
		return findings, 0, applyErr
	}

	// Plain path.
	start := time.Now()
	findings, applyErr := r.ApplyAll(ctx, func(evt modules.ModuleEvent) {
		printerInfo(p, applyRowStr(evt))
	})
	return findings, time.Since(start), applyErr
}

// runApplyAnimated drives a live tui.LiveTable for the apply phase.
func runApplyAnimated(ctx context.Context, r *modules.Runner) ([]modules.Finding, error) {
	table := tui.NewLiveTable()
	resultCh := make(chan struct {
		findings []modules.Finding
		err      error
	}, 1)

	go func() {
		findings, err := r.ApplyAll(ctx, func(evt modules.ModuleEvent) {
			table.SendRow(tui.RowEvent{
				Module:   evt.Module,
				Index:    evt.Index,
				Total:    evt.Total,
				HasError: evt.ApplyErr != nil,
				ErrMsg:   firstFindingMessage(evt.Findings, evt.ApplyErr),
				HasWarn:  hasFindingSeverity(evt.Findings, modules.SeverityWarning),
				WarnMsg:  firstFindingMessage(evt.Findings, nil),
			})
		})
		table.Done(err)
		resultCh <- struct {
			findings []modules.Finding
			err      error
		}{findings, err}
	}()

	if _, err := runTableProgram(table); err != nil {
		return nil, err
	}

	res := <-resultCh
	return res.findings, res.err
}

// runTableProgram runs the LiveTable as a Bubble Tea program and returns
// the final model. Factored out to keep animated helpers small.
func runTableProgram(table *tui.LiveTable) (*tui.LiveTable, error) {
	// Import bubbletea to run the program.
	// We run via tui.RunLiveTable to avoid direct bubbletea import here.
	return tui.RunLiveTable(table)
}

// sudoActionsFromActions returns the display strings for actions that require
// elevated privileges (sudo). The caller uses this for both the printSudoNotice
// display and the ConfirmBlast summary.
func sudoActionsFromActions(actions []modules.Action) []string {
	sudoKeywords := []string{
		"pmset",          // power module (macOS)
		"systemctl",      // Linux daemon management
		"socketfilterfw", // macOS application firewall
	}

	var result []string
	for _, a := range actions {
		for _, kw := range sudoKeywords {
			if strings.Contains(strings.ToLower(a.Description), kw) ||
				strings.Contains(strings.ToLower(a.Module), kw) {
				result = append(result, fmt.Sprintf("%-18s %s", a.Module, styleMuted.Render(a.Description)))
				break
			}
		}
	}
	return result
}

// printSudoNotice warns the user that some planned actions require sudo,
// listing exactly which ones so there are no surprises when the password prompt appears.
func printSudoNotice(p Printer, actions []modules.Action) {
	sudoActions := sudoActionsFromActions(actions)
	if len(sudoActions) == 0 {
		return
	}

	printerInfo(p, "")
	printerInfo(p, "  "+styleWarn.Render("⚠")+"  "+styleBold.Render("sudo required")+"  "+styleMuted.Render("your macOS/Linux password will be requested for:"))
	printerInfo(p, "")
	for _, line := range sudoActions {
		printerInfo(p, "    "+line)
	}
	printerInfo(p, "")
}

// Consolidated into one function to keep newUpCmd's cyclomatic complexity below 15.
func applyTimeGates(cmd *cobra.Command, p Printer, cc *cmdContext, findings []modules.Finding) error {
	// Gate 1: tailscaled must be reachable — everything depends on it.
	if err := requireTailscaleDaemon(p); err != nil {
		return err
	}
	// Gate 2: SSH re-auth interval may not be raised above 12h without consent.
	// §7 note 7 fires when the user has explicitly configured a non-default period.
	accept, _ := cmd.Flags().GetBool("accept-checkperiod-extension")
	if d, parseErr := time.ParseDuration(cc.cfg.Mobile.SSHCheckPeriod); parseErr == nil && d > 0 {
		emitSecurityNote(p, cc.jsonOut, "ssh-checkperiod") // §7 note 7 — fires on conditional branch when period is configured
	}
	if err := checkPeriodGate(cc.cfg, accept); err != nil {
		return err
	}
	// Gate 3: never configure remote access on an unencrypted disk.
	// §7 note 5 fires here when disk encryption is required.
	if blockers := diskEncryptionBlockers(findings); len(blockers) > 0 {
		emitSecurityNote(p, cc.jsonOut, "disk-encryption") // §7 note 5
		forceUnsafe, _ := cmd.Flags().GetBool("force-unsafe")
		if !forceUnsafe {
			for _, b := range blockers {
				printerError(p, "  ✗  "+b.Message)
			}
			return fmt.Errorf("up: refusing to apply — full-disk encryption is required (fail-closed); enable it, or re-run with --force-unsafe to override (NOT recommended)")
		}
		slog.Warn("up: --force-unsafe set — applying despite disk encryption being disabled; remote access on an unencrypted disk is dangerous")
	}
	return nil
}

// requireTailscaleDaemon ensures tailscaled is running before apply.
// If the daemon is down it starts it automatically (same as `abysslink init` does)
// and polls up to 15 s. The tailscale module's Apply handles `tailscale up`
// (browser auth) interactively — this function only starts the daemon socket.
func requireTailscaleDaemon(p Printer) error {
	ctx := context.Background()
	runner := &shell.ExecRunner{}

	if res, err := runner.Run(ctx, "tailscale", "status"); err == nil && res.ExitCode == 0 {
		return nil // already running
	}

	printerInfo(p, "")
	printerInfo(p, "  "+iconWarnStr()+"  tailscaled not running — starting...")

	plat, err := platformauto.New(runner)
	if err != nil {
		return fmt.Errorf("up: platform detection: %w", err)
	}
	if startErr := doStartTailscaleDaemon(ctx, runner, plat); startErr != nil {
		printerInfo(p, "  "+iconWarnStr()+"  start command failed: "+styleMuted.Render(startErr.Error()))
	}

	printerInfo(p, "  "+iconSpinStr()+"  Waiting for tailscaled...")
	if !waitForDaemon(ctx, runner) {
		// Show the actual tailscale status output so the user can see why.
		if diag, diagErr := runner.Run(ctx, "tailscale", "status"); diagErr == nil && diag.Stderr != "" {
			printerInfo(p, "  "+styleMuted.Render("tailscale status: "+strings.TrimSpace(diag.Stderr)))
		}
		printerInfo(p, "")
		printerInfo(p, "  "+iconFatalStr()+"  tailscaled did not start — fix manually:")
		printerInfo(p, "    "+styleCode.Render("brew services restart tailscale")+"  "+styleMuted.Render("(macOS)"))
		printerInfo(p, "    "+styleCode.Render("sudo systemctl enable --now tailscaled")+"  "+styleMuted.Render("(Linux)"))
		printerInfo(p, "")
		return fmt.Errorf("up: tailscaled did not start within 15s")
	}

	printerInfo(p, "  "+iconDoneStr()+"  tailscaled ready")
	printerInfo(p, "")
	return nil
}

// checkPeriodGate enforces the immutable default that the SSH re-auth interval
// is never raised above 12h without explicit consent. Values at or below 12h
// (settable down) always pass.
func checkPeriodGate(cfg *config.Config, accept bool) error {
	d, err := time.ParseDuration(cfg.Mobile.SSHCheckPeriod)
	if err != nil {
		// Fail closed: a malformed duration must NOT silently bypass the 12h
		// re-auth floor (an immutable security default). WR-07.
		return fmt.Errorf("up: ssh_check_period %q is not a valid duration; refusing to apply (fail-closed)", cfg.Mobile.SSHCheckPeriod)
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

// optionalACLPort describes a module that needs a non-default Tailscale ACL grant.
type optionalACLPort struct {
	module string
	port   string
}

// optionalACLPorts returns the set of enabled modules whose ports are not
// covered by the default ACL (SSH tcp/22 + ntfy tcp/2586 + mosh udp/60000-61000).
// Every entry here requires an explicit `abysslink acl push` before the phone
// can reach the service.
func optionalACLPorts(cfg *config.Config) []optionalACLPort {
	var out []optionalACLPort
	if cfg.Modules.CodeServer.Enabled {
		out = append(out, optionalACLPort{"code-server", "tcp/8080"})
	}
	if cfg.Modules.Ttyd.Enabled {
		out = append(out, optionalACLPort{"ttyd", "tcp/7681"})
	}
	if cfg.Modules.EternalTerminal.Enabled {
		out = append(out, optionalACLPort{"eternal-terminal", "tcp/2022"})
	}
	if cfg.Modules.Syncthing.Enabled {
		out = append(out, optionalACLPort{"syncthing", "tcp/8384"})
	}
	if cfg.Modules.Upsnap.Enabled {
		out = append(out, optionalACLPort{"upsnap", "tcp/8090"})
	}
	return out
}

// printNextSteps prints a styled box for findings that require manual action.
func printNextSteps(p Printer, findings []modules.Finding, cfg *config.Config) {
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

	// ACL reminder: any enabled module whose port is not covered by the default
	// ACL (SSH + mosh) needs an explicit acl push before the phone can reach it.
	if cfg != nil {
		if ports := optionalACLPorts(cfg); len(ports) > 0 {
			lines := []string{
				"These modules need Tailscale ACL grants to be reachable from your phone:",
				"",
			}
			for _, op := range ports {
				lines = append(lines, "  "+styleCode.Render(fmt.Sprintf("%-18s", op.module))+" → "+op.port)
			}
			lines = append(lines,
				"",
				"Apply the ACL now:",
				"  "+styleCode.Render("abysslink acl push"),
				"  "+styleCode.Render("abysslink acl push --manual")+"  (no OAuth credentials)",
			)
			steps = append(steps, step{
				title: styleWarn.Render("ACL port grants required"),
				lines: lines,
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

// printSuccessSummary shows a "you're done" box after a clean apply, telling the
// user exactly what they have and how to connect from their phone.
func printSuccessSummary(p Printer, cfg *config.Config) {
	if cfg == nil {
		return
	}
	hostname := cfg.Tailnet.Hostname
	if hostname == "" {
		hostname = "<your-rig>"
	}

	var sb strings.Builder
	sb.WriteString(styleSuccess.Render("✓  Your rig is ready") + "\n\n")
	sb.WriteString(styleBold.Render("Connect from your phone:") + "\n")

	if cfg.Modules.Mosh.Enabled && cfg.Modules.Tmux.Enabled {
		sb.WriteString("  " + styleCode.Render(fmt.Sprintf("mosh %s -- tmux new -A -s main", hostname)) + "\n")
	} else if cfg.Modules.Tmux.Enabled {
		sb.WriteString("  " + styleCode.Render(fmt.Sprintf("ssh %s -t tmux new -A -s main", hostname)) + "\n")
	} else {
		sb.WriteString("  " + styleCode.Render(fmt.Sprintf("ssh %s", hostname)) + "\n")
	}

	sb.WriteString("\n" + styleMuted.Render("Next: pair your phone →  ") +
		styleCode.Render("abysslink enroll phone"))

	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorGreen).
		Padding(1, 2).
		Width(54)
	printerInfo(p, style.Render(strings.TrimRight(sb.String(), "\n")))
	printerInfo(p, "")
}
