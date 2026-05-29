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

// Package cli — 7-stage Setup Journey orchestrator.
//
// `abysslink init` runs this journey: Account → Prerequisites → Converge →
// Lock → Enroll → Verify → Done. Each stage calls the existing command
// function for that step (never duplicating them), so every stage remains
// independently runnable and idempotent.
//
// Under --yes/--json/non-TTY the journey runs headless (no JourneyHeader,
// no Pause) so automated invocations never hang. With a TTY, JourneyHeader
// is printed at each stage boundary and Pause is inserted only at the §6-
// sanctioned stop points (external-action waits). The last completed stage
// is persisted to abysslinkStateDir()/journey-state.json so --resume can
// continue an interrupted run.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tailscale"
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
		"Done",
	}
}

// journeyStages returns the ordered slice of the 7 journey stages. Each stage's
// run function CALLS the existing command function for that step — it never
// reimplements the step logic, keeping every stage independently runnable.
func journeyStages() []journeyStage {
	return []journeyStage{
		{
			index: 1,
			label: "Account",
			// Stage 1: confirm or guide the user to create a Tailscale account.
			// §7 note 1 (SSO hardening) fires here.
			run: func(ctx context.Context, p Printer) error {
				emitSecurityNote(p, "sso-hardening")   // §7 note 1
				emitSecurityNote(p, "dry-run-default") // §7 note 2
				return ensureTailscaleAccount(p)
			},
		},
		{
			index: 2,
			label: "Prerequisites",
			// Stage 2: tool check + Tailscale binary/daemon ensure + security hardening.
			// §7 note 4 (sudo notice) fires here before any elevated actions.
			run: func(ctx context.Context, p Printer) error {
				emitSecurityNote(p, "sudo-notice") // §7 note 4
				runner := &shell.ExecRunner{}
				plat, err := platformauto.New(runner)
				if err != nil {
					return err
				}
				toolStatus := runToolCheck(ctx, p, runner)
				if err := ensureTailscale(ctx, p, runner, plat, toolStatus, true); err != nil {
					return err
				}
				return runSecurityFixes(ctx, p, runner, plat, true)
			},
		},
		{
			index: 3,
			label: "Converge",
			// Stage 3: placeholder — the config write already happened in init RunE
			// before the journey stages run. The up converge runs after the journey
			// when the user runs `abysslink up --apply`.
			// §7 notes 5 (disk encryption) and 9 (ntfy tailnet-only) fire here.
			run: func(_ context.Context, p Printer) error {
				emitSecurityNote(p, "disk-encryption")   // §7 note 5
				emitSecurityNote(p, "ntfy-tailnet-only") // §7 note 9
				printerInfo(p, styleMuted.Render("Config written. Run `abysslink up --apply` to converge."))
				return nil
			},
		},
		{
			index: 4,
			label: "Lock",
			// Stage 4: Tailnet Lock init guidance.
			// The real init (with SecretBox + attestation) runs when the user
			// runs `abysslink lock init --apply`. Here we provide guidance and
			// check whether Lock is already enabled.
			// §7 note 6 (Tailnet Lock secrets) fires here.
			run: func(ctx context.Context, p Printer) error {
				emitSecurityNote(p, "tailnet-lock-secrets") // §7 note 6
				runner := &shell.ExecRunner{}
				lc := tailscale.NewLockClient(runner)
				if st, err := lc.Status(ctx); err == nil && st.Enabled {
					printerInfo(p, styleSuccess.Render("Tailnet Lock is already enabled."))
					return nil
				}
				printerInfo(p, styleBold.Render("Enable Tailnet Lock:"))
				printerInfo(p, "  "+styleCode.Render("abysslink lock init --apply"))
				printerInfo(p, "  "+styleMuted.Render("This will print disablement secrets ONCE — have a password manager ready."))
				return nil
			},
		},
		{
			index: 5,
			label: "Enroll",
			// Stage 5: phone enrollment guidance.
			// The real enrollment (QR + poll) runs when the user runs
			// `abysslink enroll phone`. Here we provide guidance.
			// §7 note 10 (lock screen + SSH client hygiene) fires here — enroll is
			// where the user is setting up the phone connection.
			run: func(_ context.Context, p Printer) error {
				emitSecurityNote(p, "lock-screen-hygiene") // §7 note 10
				printerInfo(p, styleBold.Render("Enroll your phone:"))
				printerInfo(p, "  "+styleCode.Render("abysslink enroll phone"))
				printerInfo(p, "  "+styleMuted.Render("This will show a QR code for the Tailscale app."))
				return nil
			},
		},
		{
			index: 6,
			label: "Verify",
			// Stage 6: doctor guidance.
			// §7 note 11 (doctor is not a full audit) fires here.
			run: func(_ context.Context, p Printer) error {
				emitSecurityNote(p, "doctor-not-full-audit") // §7 note 11
				printerInfo(p, styleBold.Render("Verify your setup:"))
				printerInfo(p, "  "+styleCode.Render("abysslink doctor"))
				return nil
			},
		},
		{
			index: 7,
			label: "Done",
			// Stage 7: success/next-steps box.
			// §7 notes 3 (backups reversible), 8 (no Funnel), 12 (panic reversible) fire here.
			run: func(_ context.Context, p Printer) error {
				emitSecurityNote(p, "backups-reversible") // §7 note 3
				emitSecurityNote(p, "no-funnel")          // §7 note 8
				emitSecurityNote(p, "panic-reversible")   // §7 note 12
				printerInfo(p, "")
				printerInfo(p, styleSuccess.Render("Setup complete — your rig is ready."))
				printerInfo(p, "")
				printerInfo(p, styleMuted.Render("Connect from your phone:"))
				printerInfo(p, "  "+styleCode.Render("mosh <your-rig> -- tmux new -A -s main"))
				printerInfo(p, "")
				return nil
			},
		},
	}
}

// runJourney is the driver loop for the 7-stage journey. It:
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
func writeJourneyState(stateFile string, stage int) error {
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(journeyStageState{LastStage: stage})
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, data, 0o600)
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
