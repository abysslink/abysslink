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

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// asciinemaCredWarning is the non-suppressible credential warning shown before
// every `abysslink asciinema rec`. Terminal recordings capture everything that
// scrolls past — including secrets echoed to the screen, prompt content, and
// command output. There is intentionally no flag or env-var to bypass it
// (HARD FLOOR, T-21-02-01).
//
//nolint:gosec // G101: this is a user-facing warning message about credentials, not a hardcoded credential
const asciinemaCredWarning = `WARNING — terminal recording captures CREDENTIALS.

asciinema records EVERYTHING printed to this terminal, including:
  - secrets, tokens, and passwords echoed to the screen
  - command output that may contain private keys or session cookies
  - your terminal scrollback, which is effectively a credential store

Before you record:
  - close any session with live secrets on screen
  - never paste an API key, password, or recovery phrase during the recording
  - review the .cast file before sharing — it is plain text

Press Enter to acknowledge and start recording, or Ctrl-C to abort.`

// newAsciinemaCmd returns the `abysslink asciinema` command group. Its sole
// subcommand, `rec`, wraps `asciinema rec` behind a non-suppressible credential
// warning that can only be shown in a live TTY.
func newAsciinemaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "asciinema",
		Short: "Record terminal sessions with a credential-safety guardrail",
		Long: `Wrap the asciinema terminal recorder with abysslink's safety guardrail.

Terminal recordings capture every secret that scrolls past, so abysslink shows a
non-suppressible credential warning before any recording starts. There is no flag
or environment variable to skip the warning, and recording is refused outside a
live interactive terminal.`,
	}
	cmd.AddCommand(newAsciinemaRecCmd())
	return cmd
}

// newAsciinemaRecCmd returns the `abysslink asciinema rec [file]` subcommand.
func newAsciinemaRecCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rec [file]",
		Short: "Record a terminal session (shows a non-suppressible credential warning first)",
		Long: `Record a terminal session with asciinema.

A non-suppressible credential warning is shown before recording begins. Because
the warning can only be presented in a live terminal, this command refuses to run
in non-interactive contexts (--yes, --json, piped stdin, or CI): there is no way
to silently skip the warning.

Any positional argument is passed through to asciinema as the output file.`,
		Example: `  # Record to an auto-named cast file (warning shown first)
  abysslink asciinema rec

  # Record to a specific file
  abysslink asciinema rec demo.cast`,
		Args: cobra.MaximumNArgs(1),
	}

	cmd.RunE = func(c *cobra.Command, args []string) error {
		cc, err := loadCmdContext(c)
		if err != nil {
			return err
		}
		deps, err := buildDeps(c.Context(), cc)
		if err != nil {
			return err
		}
		return runAsciinemaRec(c.Context(), interactive(cc.yes, cc.jsonOut), deps.Prompt, cc.runner, args)
	}

	return cmd
}

// runAsciinemaRec enforces the HARD FLOOR credential-warning gate and then runs
// `asciinema rec`. It is split out from the cobra wiring so it can be unit-tested
// with an explicit interactivity flag and an injected prompt/runner.
//
// Ordering invariant (T-21-02-01 / T-21-02-04):
//  1. Reject non-interactive contexts BEFORE anything else — the warning cannot
//     be shown without a TTY, and there is no bypass.
//  2. Fail closed if no prompt is wired (nil) — never skip the warning.
//  3. Show the warning via prompt; abort on error.
//  4. Only then exec `asciinema rec` over an interactive TTY (discrete argv, no
//     sh -c).
func runAsciinemaRec(ctx context.Context, isInteractive bool, prompt func(ctx context.Context, msg string) error, runner shell.Runner, args []string) error {
	if !isInteractive {
		return fmt.Errorf("asciinema rec: terminal required — the credential warning cannot be shown in non-interactive mode (--yes/--json/non-TTY); run asciinema rec in a live terminal")
	}
	if prompt == nil {
		// Fail closed: an interactive recording with no way to show the warning
		// must error, never proceed (HARD FLOOR).
		return fmt.Errorf("asciinema rec: credential warning unavailable — refusing to record without showing the warning")
	}
	if err := prompt(ctx, asciinemaCredWarning); err != nil {
		return fmt.Errorf("asciinema rec: %w", err)
	}

	recArgs := append([]string{"rec"}, args...)
	if err := runner.RunInteractive(ctx, "asciinema", recArgs...); err != nil {
		return fmt.Errorf("asciinema rec: %w", err)
	}
	return nil
}
