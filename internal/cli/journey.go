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

// Package cli — 8-stage Setup Journey orchestrator.
//
// `abysslink init` runs this journey: Account → Prerequisites → Converge →
// Lock → Enroll → Verify → ACL → Done. Each stage calls the existing command
// function for that step (never duplicating them), so every stage remains
// independently runnable and idempotent.
//
// Under --yes/--json/non-TTY the journey runs headless (no JourneyHeader) so
// automated invocations never hang (T-10-16). With a TTY, each stage pauses for
// user confirmation; stages 3–7 offer to invoke the underlying command directly.
// The headless path (autoYes=true or non-TTY) remains non-blocking in all cases.
// Security notes are suppressed under --json. The last completed stage is
// persisted to abysslinkStateDir()/journey-state.json so --resume can continue an
// interrupted run.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/charmbracelet/huh"
	cterm "github.com/charmbracelet/x/term"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tui"
)

// journeyStageFile is the filename within abysslinkStateDir() where the last
// completed stage is persisted. Contains only {"last_stage": N} — no secrets.
const journeyStageFile = "journey-state.json"

// journeyStageState is the on-disk JSON schema. Intentionally minimal: only an
// integer stage index; no credentials, tokens, or sensitive data ever written here.
type journeyStageState struct {
	LastStage int `json:"last_stage"`
}

// journeyStage describes one step in the setup journey.
type journeyStage struct {
	index int
	label string
	run   func(ctx context.Context, p Printer) error
}

// journeyLabels returns the short label list for JourneyHeader, in order.
func journeyLabels() []string {
	return []string{
		"Account",
		"Prerequisites",
		"Converge",
		"Lock",
		"Enroll",
		"Verify",
		"ACL",
		"Done",
	}
}

// journeyOfferRun presents a huh.NewConfirm prompt and, if confirmed, calls
// runner.RunInteractive with the given command. Non-fatal on run failure: warnMsg
// is printed (or the default "Command failed — run it manually later." when warnMsg
// is empty) and nil is returned so the stage doesn't abort the journey.
//
// warnMsg is the caller-supplied failure warning; pass "" for the default.
//
// The function is a no-op (returns nil without prompting) when stdin is not a TTY,
// so it is safe to call unconditionally — callers do not need to gate on stdinIsTTY().
//
// Terminal-state contract: huh leaves the terminal in raw mode after its form
// exits. journeyOfferRun captures the controlling-tty (/dev/tty) state with
// cterm.GetState before the form, and restores it with cterm.Restore after the
// form returns (success or error), before calling RunInteractive. /dev/tty (not
// os.Stdin) is used because huh drives that descriptor directly. This ensures the
// child process starts from a clean cooked-mode terminal rather than inheriting
// huh's raw-mode state.
func journeyOfferRun(ctx context.Context, p Printer, runner shell.Runner, title, desc, affirm, neg, warnMsg string, args ...string) error {
	// Argv guard: args[0] is indexed unconditionally below; reject an empty
	// argv up front rather than panicking (no panics in normal control flow).
	if len(args) == 0 {
		return errors.New("journeyOfferRun: no command supplied")
	}

	// Non-TTY guard: skip the prompt entirely when stdin is not a terminal.
	// This keeps journeyOfferRun safe in CI, pipes, and go test contexts.
	if !stdinIsTTY() {
		return nil
	}

	// huh puts the terminal in raw mode; restore to cooked mode before spawning
	// the child so the child's own raw-mode setup starts from a clean state.
	//
	// huh opens and drives /dev/tty directly (not os.Stdin), so the save/restore
	// must operate on the controlling-tty descriptor — not os.Stdin, which may be
	// a redirected file even when a controlling terminal is attached (WR-04).
	// If /dev/tty cannot be opened or its state cannot be read, log and skip the
	// restore rather than silently discarding the error.
	var (
		ttyFD      uintptr
		savedState *cterm.State
	)
	if tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDWR, 0); ttyErr == nil {
		defer func() { _ = tty.Close() }()
		ttyFD = tty.Fd()
		if st, stErr := cterm.GetState(ttyFD); stErr == nil {
			savedState = st
		} else {
			slog.Debug("journeyOfferRun: GetState failed; terminal restore skipped", "error", stErr)
		}
	} else {
		slog.Debug("journeyOfferRun: open /dev/tty failed; terminal restore skipped", "error", ttyErr)
	}

	var runNow bool
	formErr := huh.NewConfirm().
		Title(title).
		Description(desc).
		Affirmative(affirm).
		Negative(neg).
		Value(&runNow).Run()

	// Restore terminal to cooked mode regardless of whether the form succeeded.
	if savedState != nil {
		_ = cterm.Restore(ttyFD, savedState)
	}

	if formErr != nil {
		return formErr
	}

	if runNow {
		if err := runner.RunInteractive(ctx, args[0], args[1:]...); err != nil {
			msg := warnMsg
			if msg == "" {
				msg = "Command failed — run it manually later."
			}
			printerInfo(p, "  "+iconWarnStr()+"  "+msg)
		}
	}
	return nil
}

// journeyStageAccount is the run closure for Stage 1 (Account).
func journeyStageAccount(jsonOut bool, runner shell.Runner, autoYes bool) func(ctx context.Context, p Printer) error {
	return func(ctx context.Context, p Printer) error {
		emitSecurityNote(p, jsonOut, "sso-hardening")   // §7 note 1
		emitSecurityNote(p, jsonOut, "dry-run-default") // §7 note 2
		if err := ensureTailscaleAccount(ctx, p, runner, autoYes); err != nil {
			return err
		}
		return tui.Pause(ctx, "Stage 1 complete — account ready", autoYes)
	}
}

// journeyStagePrereqs is the run closure for Stage 2 (Prerequisites).
// Prerequisites were already verified in cmd_init RunE before the journey started;
// this stage emits a summary note and gate-pause only — it must NOT re-run
// ensureTailscale or runSecurityFixes (B2 fix).
func journeyStagePrereqs(jsonOut bool, autoYes bool) func(ctx context.Context, p Printer) error {
	return func(ctx context.Context, p Printer) error {
		emitSecurityNote(p, jsonOut, "sudo-notice") // §7 note 4
		printerInfo(p, styleSuccess.Render("Prerequisites verified."))
		return tui.Pause(ctx, "Stage 2 complete — prerequisites ready", autoYes)
	}
}

// journeyStageConverge is the run closure for Stage 3 (Converge).
func journeyStageConverge(jsonOut bool, runner shell.Runner, autoYes bool) func(ctx context.Context, p Printer) error {
	return func(ctx context.Context, p Printer) error {
		emitSecurityNote(p, jsonOut, "disk-encryption")   // §7 note 5
		emitSecurityNote(p, jsonOut, "ntfy-tailnet-only") // §7 note 9
		printerInfo(p, styleMuted.Render("Config written. Run `abysslink up --apply` to converge."))
		if autoYes || !interactive(autoYes, jsonOut) {
			return nil
		}
		return journeyOfferRun(ctx, p, runner,
			"Run `abysslink up --apply` now?",
			"Converges your system to match abysslink.yaml.",
			"Yes, run it", "No, I'll run it later",
			"", // default failure message
			selfExecutable(), "up", "--apply")
	}
}

// journeyStageConverge is the run closure for Stage 4 (Lock).
func journeyStageLock(jsonOut bool, cfg *config.Config, runner shell.Runner, autoYes bool) func(ctx context.Context, p Printer) error {
	return func(ctx context.Context, p Printer) error {
		emitSecurityNote(p, jsonOut, "tailnet-lock-secrets") // §7 note 6
		b, bErr := backend.New(cfg, runner)
		if bErr == nil {
			if locker, ok := b.(backend.Locker); ok {
				if st, err := locker.LockStatus(ctx); err == nil && st.Enabled {
					printerInfo(p, styleSuccess.Render("Tailnet Lock is already enabled."))
					return nil
				}
			}
		}
		printerInfo(p, styleBold.Render("Enable Tailnet Lock:"))
		printerInfo(p, "  "+styleCode.Render("abysslink lock init --apply"))
		printerInfo(p, "  "+styleMuted.Render("This will print disablement secrets ONCE — have a password manager ready."))
		if autoYes || !interactive(autoYes, jsonOut) {
			return nil
		}
		return journeyOfferRun(ctx, p, runner,
			"Run `abysslink lock init --apply` now?",
			"Enables Tailnet Lock — disablement secrets printed ONCE.",
			"Yes, run it", "No, I'll run it later",
			"", // default failure message
			selfExecutable(), "lock", "init", "--apply")
	}
}

// journeyStageEnroll is the run closure for Stage 5 (Enroll).
func journeyStageEnroll(jsonOut bool, runner shell.Runner, autoYes bool) func(ctx context.Context, p Printer) error {
	return func(ctx context.Context, p Printer) error {
		emitSecurityNote(p, jsonOut, "lock-screen-hygiene") // §7 note 10
		printerInfo(p, styleBold.Render("Enroll your phone:"))
		printerInfo(p, "  "+styleCode.Render("abysslink enroll phone"))
		printerInfo(p, "  "+styleMuted.Render("This will show a QR code for the Tailscale app."))
		if autoYes || !interactive(autoYes, jsonOut) {
			return nil
		}
		return journeyOfferRun(ctx, p, runner,
			"Run `abysslink enroll phone` now?",
			"Shows a QR code for the Tailscale app.",
			"Yes, run it", "No, I'll run it later",
			"", // default failure message
			selfExecutable(), "enroll", "phone")
	}
}

// journeyStageVerify is the run closure for Stage 6 (Verify).
func journeyStageVerify(jsonOut bool, runner shell.Runner, autoYes bool) func(ctx context.Context, p Printer) error {
	return func(ctx context.Context, p Printer) error {
		emitSecurityNote(p, jsonOut, "doctor-not-full-audit") // §7 note 11
		printerInfo(p, styleBold.Render("Verify your setup:"))
		printerInfo(p, "  "+styleCode.Render("abysslink doctor"))
		if autoYes || !interactive(autoYes, jsonOut) {
			return nil
		}
		return journeyOfferRun(ctx, p, runner,
			"Run `abysslink doctor` now?",
			"Checks all modules for misconfigurations.",
			"Yes, run it", "No, I'll run it later",
			"", // default failure message
			selfExecutable(), "doctor")
	}
}

// journeyStageACL is the run closure for Stage 7 (ACL).
// It delegates to journeyOfferRun so the terminal-restore logic and custom failure
// message live in a single place — no inline huh block.
func journeyStageACL(jsonOut bool, runner shell.Runner, autoYes bool) func(ctx context.Context, p Printer) error {
	return func(ctx context.Context, p Printer) error {
		printerInfo(p, styleBold.Render("Configure the tailnet ACL:"))
		printerInfo(p, "  "+styleCode.Render("abysslink acl push --apply"))
		printerInfo(p, "  "+styleMuted.Render("Requires tailnet.admin OAuth config — if absent, manage at:"))
		printerInfo(p, "  "+styleCode.Render("https://login.tailscale.com/admin/acls/file"))
		if autoYes || !interactive(autoYes, jsonOut) {
			return nil
		}
		return journeyOfferRun(ctx, p, runner,
			"Run `abysslink acl push --apply` now?",
			"Pushes the abysslink ACL to your tailnet. Requires OAuth config.",
			"Yes, push ACL", "No, I'll manage it manually",
			"ACL push failed — manage manually at the URL above.",
			selfExecutable(), "acl", "push", "--apply")
	}
}

// journeyStageDone is the run closure for Stage 8 (Done).
func journeyStageDone(jsonOut bool) func(ctx context.Context, p Printer) error {
	return func(_ context.Context, p Printer) error {
		emitSecurityNote(p, jsonOut, "backups-reversible") // §7 note 3
		emitSecurityNote(p, jsonOut, "no-funnel")          // §7 note 8
		emitSecurityNote(p, jsonOut, "panic-reversible")   // §7 note 12
		printerInfo(p, "")
		printerInfo(p, styleSuccess.Render("Setup complete — your rig is ready."))
		printerInfo(p, "")
		printerInfo(p, styleMuted.Render("Connect from your phone:"))
		printerInfo(p, "  "+styleCode.Render("mosh <your-rig> -- tmux new -A -s main"))
		printerInfo(p, "")
		return nil
	}
}

// journeyStages returns the ordered slice of the 8 journey stages. Each stage's
// run function CALLS the existing command function for that step — it never
// reimplements the step logic, keeping every stage independently runnable.
//
// cfg is the config the user just wrote in init; it is threaded into stage 4
// (Lock) so the "already enabled?" probe queries the backend the user
// configured rather than synthesizing config.Defaults() (which would always
// resolve to the tailscale adapter once a second backend exists — WR-05).
func journeyStages(jsonOut bool, cfg *config.Config, runner shell.Runner, autoYes bool) []journeyStage {
	return []journeyStage{
		{index: 1, label: "Account", run: journeyStageAccount(jsonOut, runner, autoYes)},
		{index: 2, label: "Prerequisites", run: journeyStagePrereqs(jsonOut, autoYes)},
		{index: 3, label: "Converge", run: journeyStageConverge(jsonOut, runner, autoYes)},
		{index: 4, label: "Lock", run: journeyStageLock(jsonOut, cfg, runner, autoYes)},
		{index: 5, label: "Enroll", run: journeyStageEnroll(jsonOut, runner, autoYes)},
		{index: 6, label: "Verify", run: journeyStageVerify(jsonOut, runner, autoYes)},
		{index: 7, label: "ACL", run: journeyStageACL(jsonOut, runner, autoYes)},
		{index: 8, label: "Done", run: journeyStageDone(jsonOut)},
	}
}

// runJourney is the driver loop for the 8-stage journey. It:
//   - Prints a JourneyHeader at each stage boundary (unless non-interactive)
//   - Skips stages up to (but not including) resumeFrom+1
//   - Runs each stage function
//   - Persists the completed stage to stateFile after each stage
//
// Under autoYes=true (--yes/--json/non-TTY) the journey runs headless:
// JourneyHeader is omitted and stages run without interactive output.
// This ensures the journey never hangs in CI or pipe contexts (T-10-16).
func runJourney(ctx context.Context, p Printer, stages []journeyStage, resumeFrom int, stateFile string, autoYes bool) error {
	// Use journeyLabels() as the canonical label source so the header matches
	// the standard label set even when stages is a stub slice (e.g. in tests).
	labels := journeyLabels()
	if len(labels) < len(stages) {
		// Fallback: build from stage labels for non-standard stage lists (tests).
		labels = make([]string, len(stages))
		for i, s := range stages {
			labels[i] = s.label
		}
	}

	for _, s := range stages {
		if s.index <= resumeFrom {
			continue // already completed before resume
		}

		// Print stage header (interactive path only, T-10-16).
		if !autoYes {
			header := tui.JourneyHeader(s.index, len(stages), labels)
			printerInfo(p, header)
			printerInfo(p, "")
		}

		if err := s.run(ctx, p); err != nil {
			return err
		}

		// Persist the completed stage. Non-fatal if it fails.
		_ = writeJourneyState(stateFile, s.index)
	}
	return nil
}

// writeJourneyState persists the last completed stage to the state file.
// SECURITY: The file contains only {"last_stage": N} — no secrets, keys,
// or tokens. This is consistent with the "no secrets on disk" invariant (T-10-17).
// CLI-15: the write routes through internal/audit (backup + audit-log entry)
// per the CLAUDE.md mutation rule — never os.WriteFile directly. 0600 preserved.
func writeJourneyState(stateFile string, stage int) error {
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(journeyStageState{LastStage: stage})
	if err != nil {
		return err
	}
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return err
	}
	return audit.New(logPath).WriteFile(stateFile, data, 0o600, false)
}

// selfExecutable returns the path of the running abysslink binary for
// re-invoking child commands (CLI-25). os.Executable() makes `./abysslink
// init` work without abysslink on PATH; the bare name is the PATH-lookup
// fallback when resolution fails.
func selfExecutable() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return exe
	}
	return "abysslink"
}

// readJourneyState reads the last completed stage from the state file.
// Returns 0 and nil if the file does not exist (start from the beginning).
func readJourneyState(stateFile string) (int, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var st journeyStageState
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, err
	}
	return st.LastStage, nil
}
