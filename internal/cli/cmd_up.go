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
	"errors"
	"fmt"
	"log/slog"
	"os"
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

// D-04 gate: NetBird SSHCheck degradation acknowledgment.
// These named constants make the required substrings verifiable via grep in tests.
const (
	warnSSHCheckText = "WARN: SSHCheck not available on NetBird — checkPeriod enforcement disabled"
	warnSetupKeyText = "Setup-key-enrolled peers have no periodic re-auth mechanism in NetBird"
	warnSSHCheckFull = warnSSHCheckText + "\n" +
		warnSetupKeyText + "\n" +
		"Re-run with --accept-no-sshcheck to acknowledge this degradation.\n" +
		"The flag will be persisted in abysslink.yaml and is only required once."
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

			// D-04 gate: NetBird backend requires explicit --accept-no-sshcheck
			// acknowledgment before apply proceeds. Prevents silent degradation of
			// the immutable 12h checkPeriod enforcement floor (SC-1 / PR-C).
			if err := netbirdSSHCheckGate(ctx, cmd, cc, p); err != nil {
				return err
			}

			printUpHeader(p, cc.dryRun)

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
				if errors.Is(planErr, errUserAborted) {
					// CLI-11: Ctrl-C/Esc during the live scan table — stop cleanly,
					// run no confirm/apply gates, mirror the ConfirmBlast decline path.
					printerInfo(p, "  Aborted.")
					return nil
				}
				return fmt.Errorf("up: %w", planErr)
			}

			printUpPlan(p, actions, findings, cc)

			// All fail-closed gates in one block to keep cyclomatic complexity low.
			if !cc.dryRun {
				if err := applyTimeGates(cmd, p, cc, findings); err != nil {
					// W2: fail-closed gates are the documented "2 — Fatal" exit
					// class; a plain error would map to exit 1 in Execute.
					return &exitError{code: exitCodeFatal, err: err}
				}
			}

			// Pass 2 — Apply phase (only if not dry-run).
			var applyFindings []modules.Finding
			var applyErr error
			if !cc.dryRun {
				var aborted bool
				var infraErr error
				applyFindings, aborted, applyErr, infraErr = runUpApplyPhase(ctx, cmd, p, r, actions, cc)
				if aborted {
					// User explicitly declined ConfirmBlast — "Aborted." already
					// printed inside the apply phase. Skip all further output.
					return nil
				}
				if infraErr != nil {
					return infraErr
				}
			}

			// Pass 3 — Next steps + success summary (always runs when not aborted).
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
	cmd.Flags().Bool("accept-no-sshcheck", false,
		"Acknowledge SSHCheck degradation on NetBird backend (persisted to abysslink.yaml — only required once)")
	return cmd
}

// printUpPlan renders the human plan detail and, under --json, additionally
// emits one structured record per planned action so dry-run plans are
// scriptable (E1) — the prose {"msg": …} lines are not machine-parseable.
func printUpPlan(p Printer, actions []modules.Action, findings []modules.Finding, cc *cmdContext) {
	printPlanDetail(p, actions, findings, cc.dryRun, cc.explain)
	if cc.jsonOut {
		p.PrintJSON(buildPlanRecords(actions))
	}
}

// runUpApplyPhase runs the post-gate apply phase: ConfirmBlast + ApplyAll
// (runApply), deferred NetBird consent persistence (I1), the honest final
// summary (U7), and the F-59 manual-step replay. Extracted from the RunE to
// keep its gocyclo below the ceiling.
//
// Returns:
//   - aborted: the user declined ConfirmBlast or quit the live table — the
//     caller stops with no further output.
//   - applyErr: a module apply failure; the caller still prints next steps and
//     then surfaces it.
//   - infraErr: a consent-persist or manual-step failure to return immediately.
func runUpApplyPhase(ctx context.Context, cmd *cobra.Command, p Printer, r *modules.Runner, actions []modules.Action, cc *cmdContext) (findings []modules.Finding, aborted bool, applyErr error, infraErr error) {
	findings, elapsed, aborted, applyErr := runApply(ctx, cmd, p, r, actions, cc)
	if aborted {
		return nil, true, nil, nil
	}

	// I1: persist the NetBird --accept-no-sshcheck consent only AFTER the
	// user confirmed the blast prompt — never before.
	if perr := persistNetbirdConsent(cmd, cc); perr != nil {
		return findings, false, applyErr, perr
	}

	printFinalSummary(p, actions, findings, elapsed, applyErr)

	// F-59: replay manual steps modules deferred during Apply. MUST run only
	// after the live apply table is fully closed — this is the single
	// terminal owner now. Not reached on the abort path (returned above).
	if flushErr := flushManualSteps(ctx, cc, p); flushErr != nil {
		return findings, false, applyErr, fmt.Errorf("up: manual steps: %w", flushErr)
	}
	return findings, false, applyErr, nil
}

// printUpHeader renders the `abysslink up` header box: a preview-only warning
// in dry-run mode, the "applying" banner otherwise. Extracted from newUpCmd to
// keep its cyclomatic complexity below the gocyclo ceiling.
func printUpHeader(p Printer, dryRun bool) {
	if dryRun {
		header := styleTitle.Render("abysslink up") + "  " + styleWarn.Render("preview only — run with --apply to make changes")
		printerInfo(p, styleHeaderBox.Render(header))
	} else {
		header := styleTitle.Render("abysslink up") + "  " + styleSuccess.Render("✦  applying")
		printerInfo(p, styleHeaderBox.Render(header))
	}
	printerInfo(p, "")
}

// netbirdSSHCheckGate enforces D-04: on a NetBird backend, abysslink up --apply
// must not proceed unless the user has acknowledged the SSHCheck degradation.
// If --accept-no-sshcheck is set and not yet persisted, it is written to the config.
// If AcceptNoSSHCheck is already true in the config, the gate passes silently.
// The gate is a no-op for non-netbird backends; on dry-run (scan-only) runs it
// emits the WARN non-blocking (CLI-21).
func netbirdSSHCheckGate(ctx context.Context, cmd *cobra.Command, cc *cmdContext, p Printer) error {
	// Gate only applies to the netbird backend in apply mode.
	if cc.cfg.Backend.Type != "netbird" {
		return nil
	}

	// Already acknowledged in a previous run — no friction needed.
	if cc.cfg.Server.NetBird.AcceptNoSSHCheck {
		return nil
	}

	// Dry-run (scan only) does not mutate the system; the gate is informational only.
	// We still emit the WARN so the user is aware, but do not block (CLI-21).
	if cc.dryRun {
		printerInfo(p, tui.Note(tui.NoteWarn, "SSHCheck not available on NetBird", []string{
			"checkPeriod enforcement is disabled on this backend.",
			warnSetupKeyText,
		}))
		return nil
	}

	acceptFlag, _ := cmd.Flags().GetBool("accept-no-sshcheck")
	if !acceptFlag {
		// Refuse: emit the mandatory D-04 degradation message. This is a
		// fail-closed gate → documented exit code 2 (W2).
		return &exitError{code: exitCodeFatal, err: fmt.Errorf("%s", warnSSHCheckFull)}
	}

	// Flag is set but not yet persisted. Record the acknowledgment in memory
	// only — the config write happens AFTER the user confirms the blast prompt
	// (persistNetbirdConsent), so declining the apply leaves nothing persisted (I1).
	cc.cfg.Server.NetBird.AcceptNoSSHCheck = true
	cc.persistAcceptNoSSHCheck = true
	slog.Info("netbird: AcceptNoSSHCheck acknowledged; will persist after confirmation")
	_ = ctx // context available for future extension
	return nil
}

// persistNetbirdConsent writes the in-memory AcceptNoSSHCheck acknowledgment
// to abysslink.yaml. Called only after ConfirmBlast was accepted (I1): consent
// recorded at confirmation time, never on a declined run.
func persistNetbirdConsent(cmd *cobra.Command, cc *cmdContext) error {
	if !cc.persistAcceptNoSSHCheck {
		return nil
	}
	cc.persistAcceptNoSSHCheck = false
	configPath := resolveConfigPath(cmd)
	if err := config.Write(configPath, cc.cfg); err != nil {
		return fmt.Errorf("up: persist AcceptNoSSHCheck: %w", err)
	}
	slog.Info("netbird: AcceptNoSSHCheck persisted to config")
	return nil
}

// planRecord is the JSON record emitted per planned action under `up --json`
// (E1). Fields mirror modules.Action with stable lowercase names.
type planRecord struct {
	Module      string `json:"module"`
	Description string `json:"description"`
	Explain     string `json:"explain,omitempty"`
	Reversible  bool   `json:"reversible"`
}

// buildPlanRecords converts the deduplicated planned actions to JSON-safe
// records. Always returns a non-nil slice so `--json` emits [] (not null)
// for an already-converged system.
func buildPlanRecords(actions []modules.Action) []planRecord {
	unique := uniqueActions(actions)
	records := make([]planRecord, 0, len(unique))
	for _, a := range unique {
		records = append(records, planRecord{
			Module:      a.Module,
			Description: a.Description,
			Explain:     a.Explain,
			Reversible:  a.Reversible,
		})
	}
	return records
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

// errUserAborted signals that the user quit the live table (Ctrl-C/Esc) before
// the worker finished. The command must treat this as an abort: cancel the
// worker, run no further confirm/apply gates (CLI-11).
var errUserAborted = errors.New("aborted by user")

// runScanAnimated drives a live tui.LiveTable for the scan phase.
//
// CLI-11: the PlanAll worker runs under a cancelable child context. When the
// Bubble Tea program exits BEFORE the worker signalled Done (user pressed
// Ctrl-C/Esc), the worker context is cancelled, the table is drained so the
// worker can never block on SendRow, and errUserAborted is returned.
func runScanAnimated(ctx context.Context, _ Printer, r *modules.Runner, _ []modules.Module) ([]modules.Action, []modules.Finding, error) {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// F-64: buffer slog output while the tea program owns the terminal; flush
	// to stderr after the table is closed and the worker has finished (every
	// return path below first receives from resultCh, so the deferred restore
	// runs strictly after both).
	restoreLogs := captureSlog(os.Stderr)
	defer restoreLogs()

	table := tui.NewLiveTable()
	resultCh := make(chan struct {
		actions  []modules.Action
		findings []modules.Finding
		err      error
	}, 1)

	go func() {
		actions, findings, err := r.PlanAll(workerCtx, func(evt modules.ModuleEvent) {
			table.SendRow(tui.RowEvent{
				Module:     evt.Module,
				Index:      evt.Index,
				Total:      evt.Total,
				HasActions: len(evt.Actions) > 0,
				HasWarn:    hasFindingSeverity(evt.Findings, modules.SeverityWarning),
				WarnMsg:    firstFindingMessage(evt.Findings, nil),
			})
		})
		table.Done(err)
		resultCh <- struct {
			actions  []modules.Action
			findings []modules.Finding
			err      error
		}{actions, findings, err}
	}()

	final, err := runTableProgram(ctx, table)
	if err != nil || !final.Completed() {
		// UI exited before the worker finished (program error or user abort):
		// cancel the worker and drain its remaining events so it cannot block.
		cancel()
		table.Drain()
		<-resultCh // wait for the (now-cancelled) worker to wind down
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errUserAborted
	}

	res := <-resultCh
	return res.actions, res.findings, res.err
}

// interactiveActionsFromActions returns the display strings for actions that
// require raw terminal access via shell.Runner.RunInteractive. The single
// keyword is "tailscale login" (substring match, case-insensitive).
//
// Rationale: when a planned action description contains "tailscale login", the
// subprocess calls RunInteractive which wires directly to os.Stdin/os.Stdout/
// os.Stderr. Running the Bubble Tea LiveTable in raw mode concurrently causes
// stdin contention and staircase output (LF without CR). Disabling animation
// returns terminal ownership to the subprocess.
//
// This is the same rationale as the sudo path (sudoActionsFromActions), but
// kept separate so that tailscale login does NOT trigger the sudo notice text —
// it is an interactive authentication step, not a privilege-escalation step.
func interactiveActionsFromActions(actions []modules.Action) []string {
	var result []string
	for _, a := range actions {
		if strings.Contains(strings.ToLower(a.Description), "tailscale login") {
			result = append(result, fmt.Sprintf("%-18s %s", a.Module, styleMuted.Render(a.Description)))
		}
	}
	return result
}

// applyAnimationEnabled decides whether the apply phase may use the live
// Bubble Tea table. Animation is disabled — independent of TTY/color/jsonOut
// — when ANY planned action requires sudo OR when any planned action requires
// raw terminal access (e.g., tailscale login via RunInteractive).
//
// Rationale: tea.NewProgram in internal/tui.RunLiveTable owns os.Stdin while
// running. If apply spawns an interactive child (sudo password prompt or
// tailscale login browser auth via shell.ExecRunner.RunInteractive, which also
// wires cmd.Stdin = os.Stdin), the two race for stdin bytes, the interaction
// reads garbage, and Ctrl-C is swallowed by the tea event loop. Falling back
// to the plain Printer-callback path returns stdin ownership to the child
// process so the interaction works normally.
//
// Interactive subprocess actions (e.g., tailscale login) are detected
// separately from sudo (via interactiveActionsFromActions) to avoid showing the
// sudo notice for login-only plans — login is an auth step, not escalation.
// Scan-phase animation is unaffected — there is no sudo or RunInteractive on
// the scan path.
func applyAnimationEnabled(jsonOut bool, sudoLines []string, interactiveLines []string) bool {
	if len(sudoLines) > 0 {
		return false
	}
	if len(interactiveLines) > 0 {
		return false
	}
	return animationEnabled(jsonOut)
}

// runApply runs the Apply phase, wrapping with a ConfirmBlast gate and choosing
// between animated and plain output paths. Returns findings, elapsed time, aborted flag,
// and error. When the user declines ConfirmBlast, aborted=true and findings/elapsed are zero.
func runApply(ctx context.Context, cmd *cobra.Command, p Printer, r *modules.Runner, actions []modules.Action, cc *cmdContext) (findings []modules.Finding, elapsed time.Duration, aborted bool, err error) {
	unique := uniqueActions(actions)
	sudoLines := sudoActionsFromActions(unique)
	interactiveLines := interactiveActionsFromActions(unique)

	// Build a summary string for ConfirmBlast.
	var sb strings.Builder
	if len(sudoLines) > 0 {
		sb.WriteString("sudo required for:\n")
		for _, l := range sudoLines {
			sb.WriteString("  ")
			sb.WriteString(l)
			sb.WriteString("\n")
		}
	}
	summary := strings.TrimRight(sb.String(), "\n")

	// ConfirmBlast — the last gate before mutation (after fail-closed gates).
	// Skipped when cc.yes=true (ConfirmBlast handles that internally).
	// Never reached in dry-run (caller guards).
	ok, confirmErr := tui.ConfirmBlast(cmd.Context(), summary, len(unique), cc.yes)
	if confirmErr != nil {
		return nil, 0, false, fmt.Errorf("up: confirm: %w", confirmErr)
	}
	if !ok {
		printerInfo(p, "  Aborted.")
		return nil, 0, true, nil
	}

	// Proceed with apply.
	// Note: printSudoNotice is driven by sudoLines only — interactiveLines (tailscale login)
	// must NOT trigger the sudo notice, as login is an auth step, not privilege escalation.
	printSudoNotice(p, unique)
	printerInfo(p, "  "+styleMuted.Render(hrule()))
	printerInfo(p, "  "+styleBold.Render(fmt.Sprintf("Applying %d changes...", len(unique))))
	printerInfo(p, "")

	// Animation is force-disabled when any module requires sudo or any module
	// requires raw terminal access (e.g. tailscale login) so the tea program
	// does not race with the interactive subprocess for stdin. See
	// applyAnimationEnabled for the full rationale.
	animate := applyAnimationEnabled(cc.jsonOut, sudoLines, interactiveLines)
	start := time.Now()
	if animate {
		applyFindings, applyErr := runApplyAnimated(ctx, r)
		if errors.Is(applyErr, errUserAborted) {
			// CLI-11: Ctrl-C/Esc during the live apply table — treat exactly like
			// a declined ConfirmBlast: print "Aborted." and skip all further output.
			printerInfo(p, "  Aborted.")
			return nil, 0, true, nil
		}
		// U7: report the real wall-clock apply time, not a hardcoded zero.
		return applyFindings, time.Since(start), false, applyErr
	}

	// Plain path.
	applyFindings, applyErr := r.ApplyAll(ctx, func(evt modules.ModuleEvent) {
		printerInfo(p, applyRowStr(evt))
	})
	return applyFindings, time.Since(start), false, applyErr
}

// runApplyAnimated drives a live tui.LiveTable for the apply phase.
//
// CLI-11: same cancel-on-early-quit contract as runScanAnimated — when the UI
// exits before ApplyAll signalled Done, the worker context is cancelled and
// errUserAborted is returned so the command stops without further gates.
func runApplyAnimated(ctx context.Context, r *modules.Runner) ([]modules.Finding, error) {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// F-64: same slog capture contract as runScanAnimated — swap before the
	// ApplyAll worker goroutine starts, restore (and flush to stderr) only
	// after the table closed and the worker finished (resultCh received on
	// every return path).
	restoreLogs := captureSlog(os.Stderr)
	defer restoreLogs()

	// F-63: the apply-phase table must say "applying...", not "scanning...".
	table := tui.NewLiveTableWithLabel("applying...")
	resultCh := make(chan struct {
		findings []modules.Finding
		err      error
	}, 1)

	go func() {
		findings, err := r.ApplyAll(workerCtx, func(evt modules.ModuleEvent) {
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

	final, err := runTableProgram(ctx, table)
	if err != nil || !final.Completed() {
		cancel()
		table.Drain()
		<-resultCh // wait for the (now-cancelled) worker to wind down
		if err != nil {
			return nil, err
		}
		return nil, errUserAborted
	}

	res := <-resultCh
	return res.findings, res.err
}

// runTableProgram runs the LiveTable as a Bubble Tea program and returns
// the final model. Factored out to keep animated helpers small.
func runTableProgram(ctx context.Context, table *tui.LiveTable) (*tui.LiveTable, error) {
	// Import bubbletea to run the program.
	// We run via tui.RunLiveTable to avoid direct bubbletea import here. ctx is
	// threaded so a parent/SIGTERM cancel tears the program down and restores the
	// terminal instead of leaving it in raw mode.
	return tui.RunLiveTable(ctx, table)
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

	lines := append([]string{"Your macOS/Linux password will be requested for:"}, sudoActions...)
	printerInfo(p, "")
	printerInfo(p, tui.Note(tui.NoteWarn, "sudo required", lines))
	printerInfo(p, "")
}

// Consolidated into one function to keep newUpCmd's cyclomatic complexity below 15.
func applyTimeGates(cmd *cobra.Command, p Printer, cc *cmdContext, findings []modules.Finding) error {
	// Gate 1: tailscaled must be reachable — everything depends on it.
	// CLI-10: thread the signal-cancellable command context and the injected
	// runner (test seam) instead of context.Background() + a fresh ExecRunner.
	if err := requireTailscaleDaemon(cmd.Context(), p, cc.runner); err != nil {
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
		// Emit blocker messages for the user before the gate decision.
		for _, b := range blockers {
			printerError(p, "  ✗  "+b.Message)
		}
		if err := diskEncryptionGate(blockers, forceUnsafe); err != nil {
			return err
		}
	}
	return nil
}

// requireTailscaleDaemon ensures tailscaled is running before apply.
// If the daemon is genuinely down it starts it automatically (same as
// `abysslink init` does) and polls up to 15 s. The tailscale module's Apply
// handles `tailscale up` (browser auth) interactively — this function only
// starts the daemon socket.
//
// W3: the probe is probeTailscaleDaemon, NOT a bare exit-code check. A
// logged-out daemon exits non-zero with the socket up; restarting it would
// drop every live tailnet session — including the phone SSH session the user
// may be running `up` from. Only a genuinely unreachable socket triggers the
// restart, and the output says so. "Logged out" is handled by the tailscale
// module's needs_login next-step, not here.
//
// ctx and runner are injected (CLI-10): the caller's signal-cancellable context
// propagates and tests can substitute a MockRunner.
func requireTailscaleDaemon(ctx context.Context, p Printer, runner shell.Runner) error {
	if probeTailscaleDaemon(ctx, runner) {
		return nil // daemon socket reachable (running, possibly logged out) — never restart a live daemon
	}

	printerInfo(p, "")
	printerInfo(p, "  "+iconWarnStr()+"  tailscaled is not running (socket unreachable) — starting it...")

	plat, err := platformauto.New(runner)
	if err != nil {
		return fmt.Errorf("up: platform detection: %w", err)
	}
	if startErr := doStartTailscaleDaemon(ctx, runner, plat); startErr != nil {
		printerInfo(p, "  "+iconWarnStr()+"  start command failed: "+styleMuted.Render(startErr.Error()))
	}

	var daemonReady bool
	_ = spinWork(ctx, p, "Waiting for tailscaled...", func(ctx context.Context) error {
		daemonReady = waitForDaemon(ctx, runner)
		return nil
	})
	if !daemonReady {
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

// unknownDiskEncryptionMarker is the stable substring set in Plan 02 to
// distinguish a genuinely-unknown disk-encryption state (cannot be determined)
// from a known-off state (disk is confirmed unencrypted). Plan 04 gates on this
// substring to refuse --force-unsafe for unknown-state FATALs (D-05).
//
// KNOWN LIMITATION (review W10): keying a security gate off a message substring
// is fragile; a structured field (a distinct Check name such as
// "filevault-unknown", or an explicit State field on modules.Finding) would be
// robust. The emitting side lives in internal/modules/hardening — outside this
// package — and both sides document the marker as a stable cross-package
// contract, so migrating it requires a coordinated change to the hardening
// module's detect_darwin.go/detect_linux.go emitters. Tracked for the modules
// owner; do not change only one side.
const unknownDiskEncryptionMarker = "disk-encryption state is UNKNOWN"

// diskEncryptionGate applies the gate logic over a pre-filtered blocker slice
// (output of diskEncryptionBlockers). It is extracted here so tests can exercise
// it directly without standing up a full command context.
//
// Gate rules (D-05, CLAUDE.md immutable default):
//   - Any blocker carrying the UNKNOWN-state marker ⇒ refuse unconditionally;
//     --force-unsafe does NOT bypass it; error explains manual verification.
//   - Remaining (known-off) blockers ⇒ refuse unless forceUnsafe is set
//     (existing behavior, unchanged).
//   - Empty blockers ⇒ nil (no error).
func diskEncryptionGate(blockers []modules.Finding, forceUnsafe bool) error {
	if len(blockers) == 0 {
		return nil
	}

	// First pass: check for any UNKNOWN-state blocker. These are non-overridable
	// regardless of --force-unsafe (zero bypass, D-05).
	for _, b := range blockers {
		if strings.Contains(b.Message, unknownDiskEncryptionMarker) {
			return fmt.Errorf(
				"up: refusing to apply — disk-encryption state could not be determined (UNKNOWN); " +
					"verify encryption status manually (e.g. `fdesetup status` on macOS or `lsblk` on Linux) " +
					"and ensure full-disk encryption is enabled before configuring remote access; " +
					"this state cannot be overridden",
			)
		}
	}

	// Second pass: known-off blockers — refuse unless --force-unsafe is set.
	if !forceUnsafe {
		return fmt.Errorf("up: refusing to apply — full-disk encryption is required (fail-closed); enable it, or re-run with --force-unsafe to override (NOT recommended)")
	}
	slog.Warn("up: --force-unsafe set — applying despite disk encryption being disabled; remote access on an unencrypted disk is dangerous")
	return nil
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
	sb.WriteString(styleTitle.Render("Next steps"))
	sb.WriteString("\n\n")
	for i, s := range steps {
		sb.WriteString(s.title)
		sb.WriteString("\n\n")
		for _, l := range s.lines {
			sb.WriteString(l)
			sb.WriteString("\n")
		}
		if i < len(steps)-1 {
			sb.WriteString("\n")
			sb.WriteString(styleMuted.Render(hrule()))
			sb.WriteString("\n\n")
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
	sb.WriteString(styleSuccess.Render("✓  Your rig is ready"))
	sb.WriteString("\n\n")
	sb.WriteString(styleTitle.Render("Connect from your phone:"))
	sb.WriteString("\n")

	var connect string
	switch {
	case cfg.Modules.Mosh.Enabled && cfg.Modules.Tmux.Enabled:
		connect = fmt.Sprintf("mosh %s -- tmux new -A -s main", hostname)
	case cfg.Modules.Tmux.Enabled:
		connect = fmt.Sprintf("ssh %s -t tmux new -A -s main", hostname)
	default:
		connect = fmt.Sprintf("ssh %s", hostname)
	}
	sb.WriteString("  ")
	sb.WriteString(styleCode.Render(connect))
	sb.WriteString("\n")

	sb.WriteString("\n")
	sb.WriteString(styleMuted.Render("Next: pair your phone →  "))
	sb.WriteString(styleCode.Render("abysslink enroll phone"))

	style := lipgloss.NewStyle().
		Border(boxBorder()).
		BorderForeground(colorGreen).
		Padding(1, 2).
		Width(boxWidth())
	printerInfo(p, style.Render(strings.TrimRight(sb.String(), "\n")))
	printerInfo(p, "")
}
