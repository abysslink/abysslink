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

	"github.com/abysslink/abysslink/internal/browser"
	"github.com/abysslink/abysslink/internal/tui"
)

// recopyActionLabel is the option offered alongside "Continue" in manual-step
// prompts for steps that carry a Recopy action (F-60). Today the only such
// step is the ACL paste step, so the label names the ACL explicitly.
const recopyActionLabel = "Copy ACL to clipboard again"

// pauseWithActionFn matches tui.PauseWithAction. Injectable so tests can
// exercise the recopy loop without a TTY.
type pauseWithActionFn func(ctx context.Context, msg, actionLabel string, yes bool) (bool, error)

// runStepInteraction shows one manual-step prompt box. Steps without a Recopy
// action keep the plain Pause behaviour. Steps with Recopy loop: each time the
// user picks the recopy action, it re-runs the step's copy-to-clipboard
// closure (warning on failure, confirming on success) and re-shows the prompt
// until the user picks Continue (F-60). PauseWithAction short-circuits to
// (false, nil) when yes is true or stdin is not a TTY, so the loop never
// blocks non-interactive runs.
func runStepInteraction(ctx context.Context, msg string, recopy func(context.Context) error, yes bool, p Printer, pause pauseWithActionFn) error {
	if recopy == nil {
		return tui.Pause(ctx, msg, yes)
	}
	for {
		action, err := pause(ctx, msg, recopyActionLabel, yes)
		if err != nil {
			return err
		}
		if !action {
			return nil
		}
		if rerr := recopy(ctx); rerr != nil {
			p.Error(fmt.Sprintf("  ! copy failed: %v", rerr))
		} else {
			p.Print("  ✓ copied to clipboard")
		}
	}
}

// flushManualSteps replays the manual steps modules deferred via
// Deps.DeferManualStep during Apply/Repair. It MUST be called only after the
// owning command's TUI (live table) has fully closed: modules never prompt
// themselves because a second TUI on the same terminal races for stdin and
// corrupts terminal state (F-59).
//
// Per step:
//   - Non-interactive (--yes, --json, or no TTY): never block. Under --json the
//     step is listed on stderr via slog.Warn (stdout stays machine-readable);
//     otherwise the instruction body is printed via the Printer so the user can
//     complete it later.
//   - Interactive: pause on the instruction text, open the step's URL (if any)
//     in the browser, then pause on the confirmation text (if any). Steps with
//     a Recopy action additionally offer "Copy ACL to clipboard again" at both
//     pauses (F-60).
//
// The collected slice is cleared before replay so a re-entrant flush (or a
// later flush on the same cmdContext) never repeats steps. Pause errors are
// non-fatal warnings unless the context itself was cancelled.
func flushManualSteps(ctx context.Context, cc *cmdContext, p Printer) error {
	if cc.manualSteps == nil || len(*cc.manualSteps) == 0 {
		return nil
	}
	steps := *cc.manualSteps
	*cc.manualSteps = nil

	for _, s := range steps {
		if !interactive(cc.yes, cc.jsonOut) {
			if cc.jsonOut {
				// --json: stdout is machine-readable; list the step on stderr.
				slog.Warn("manual step required", "title", s.Title, "url", s.URL, "body", s.Body)
			} else {
				// --yes / non-TTY: print the full instructions so the user can
				// complete the step out-of-band. Never block.
				p.Print(s.Body)
			}
			continue
		}

		if err := runStepInteraction(ctx, s.Body, s.Recopy, cc.yes, p, tui.PauseWithAction); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("manual step prompt interrupted", "title", s.Title, "err", err)
		}
		if s.URL != "" {
			if err := browser.OpenURL(ctx, cc.runner, s.URL); err != nil {
				slog.Warn("could not open URL for manual step; visit it manually",
					"title", s.Title, "url", s.URL, "err", err)
			}
		}
		if s.Confirm != "" {
			if err := runStepInteraction(ctx, s.Confirm, s.Recopy, cc.yes, p, tui.PauseWithAction); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				slog.Warn("manual step confirmation interrupted", "title", s.Title, "err", err)
			}
		}
	}
	return nil
}
