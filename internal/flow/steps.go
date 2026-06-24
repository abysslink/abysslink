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

package flow

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// Printer is the minimal output interface that step functions accept. It is
// defined here in internal/flow (not internal/cli) to avoid the import cycle:
// internal/cli imports internal/flow, so internal/flow must NOT import
// internal/cli.
//
// The concrete implementation (cli.consolePrinter) satisfies this interface.
type Printer interface {
	Print(s string)
}

// StepFunc is the canonical signature for a guided setup step. Each step
// returns a *huh.Form that the caller (internal/cli) will run with
// form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx). Step funcs MUST NOT
// call .Run() or .RunWithContext() themselves — all IO execution belongs in
// the caller (IO boundary rule).
type StepFunc func(ctx context.Context, runner shell.Runner, printer Printer, state *FlowState) (*huh.Form, error)

// Compile-time assertions: verify each exported step function satisfies
// StepFunc. If a function signature drifts from StepFunc this file will not
// compile, catching the drift before tests run.
var (
	_ StepFunc = StepAccount
	_ StepFunc = StepPrereqs
	_ StepFunc = StepConverge
	_ StepFunc = StepLock
	_ StepFunc = StepEnroll
	_ StepFunc = StepVerify
	_ StepFunc = StepACL
	_ StepFunc = StepDone
)

// sanitizeHostname converts a raw hostname string to a lowercase DNS-safe
// value by lowercasing, replacing underscores/spaces with hyphens, and
// stripping any leading or trailing hyphens/dots.
// Ported from internal/cli/cmd_init.go:sanitizeHostname.
func sanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		case r == '_' || r == ' ':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}

// validateInitHostname is the inline form validator for the hostname input.
// It mirrors the config.Load rules so the wizard can never collect a value
// the config loader would later reject (C1).
// Ported from internal/cli/cmd_init.go:validateInitHostname.
func validateInitHostname(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("hostname is required")
	}
	if s != strings.ToLower(s) {
		return fmt.Errorf("hostname must be lowercase (try %q)", sanitizeHostname(s))
	}
	if err := config.ValidateHostname(s); err != nil {
		return fmt.Errorf("only a-z, 0-9, hyphens and dots are allowed (try %q)", sanitizeHostname(s))
	}
	return nil
}

// StepAccount builds the account setup form (Stage 0). The form collects:
//   - BackendType (tailscale / headscale / netbird) via a select
//   - Email (account identity) via a text input
//
// The returned *huh.Form MUST be run by the caller; this function never calls
// .Run() or .RunWithContext().
func StepAccount(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Backend type").
				Description("Which Tailscale-compatible control server to use").
				Options(
					huh.NewOption("Tailscale (cloud, requires account)", "tailscale"),
					huh.NewOption("Headscale (self-hosted)", "headscale"),
					huh.NewOption("NetBird (self-hosted, REST-only — SSHCheck degradation, see docs)", "netbird"),
				).
				Value(&state.BackendType),
		),
		huh.NewGroup(
			// Backend-neutral wording (U8): headscale/netbird users have no
			// "Tailscale account"; the email is the config identity.
			huh.NewInput().
				Title("Account email").
				Description("The email you sign in to your control plane with (Tailscale, Headscale, or NetBird)").
				Value(&state.Email).
				Validate(func(s string) error {
					if !strings.Contains(s, "@") {
						return fmt.Errorf("must be a valid email address")
					}
					return nil
				}),
		),
	)
	return form, nil
}

// StepPrereqs builds the prerequisites form (Stage 1). The form collects the
// rig hostname with DNS-safe validation. Prereq tool checks are handled by
// the caller before running the form.
func StepPrereqs(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Rig hostname").
				Description("This machine's tailnet hostname (pre-filled from OS, lowercase a-z0-9-.)").
				Value(&state.Hostname).
				Validate(validateInitHostname),
		),
	)
	return form, nil
}

// StepConverge builds the converge confirmation form (Stage 2). The form
// asks the user whether to run `abysslink up --apply` now. The actual shell
// command is NOT invoked here — the caller reads the form result and invokes
// the command if the user confirmed.
func StepConverge(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	var runNow bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Run `abysslink up --apply` now?").
				Description("Converges your system to match abysslink.yaml.").
				Affirmative("Yes, run it").
				Negative("No, I'll run it later").
				Value(&runNow),
		),
	)
	// Store the user's choice on the state when the caller runs the form.
	// The caller is responsible for actually executing the command.
	_ = state // state.StageConvergeDone will be set by the caller after form execution
	_ = runNow
	return form, nil
}

// StepLock builds the Tailnet Lock confirmation form (Stage 3). The form asks
// the user whether to enable Tailnet Lock now via `abysslink lock init --apply`.
// The actual command is NOT invoked here.
func StepLock(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	var runNow bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Run `abysslink lock init --apply` now?").
				Description("Enables Tailnet Lock — disablement secrets printed ONCE. Have a password manager ready.").
				Affirmative("Yes, run it").
				Negative("No, I'll run it later").
				Value(&runNow),
		),
	)
	_ = state
	_ = runNow
	return form, nil
}

// StepEnroll builds the module-enrollment form (Stage 4). The form collects
// boolean toggles for SSH, tmux, mosh, and ntfy, plus the ntfy listen port
// (validated as an integer in [1024, 65535]).
func StepEnroll(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	portStr := strconv.Itoa(state.NtfyPort)
	if state.NtfyPort == 0 {
		portStr = "2586"
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable Tailscale SSH?").
				Description("Replaces macOS Remote Login with Tailscale's cryptographically-verified SSH — no open ports, no password auth").
				Value(&state.EnableSSH),
			huh.NewConfirm().
				Title("Enable tmux?").
				Description("Keeps your terminal session alive on the rig — reconnect from your phone and pick up exactly where you left off").
				Value(&state.EnableTmux),
			huh.NewConfirm().
				Title("Enable mosh?").
				Description("Roaming shell that survives network switches on your phone (WiFi↔LTE), timeouts, and sleep — reconnects automatically").
				Value(&state.EnableMosh),
			huh.NewConfirm().
				Title("Enable ntfy push notifications?").
				Description("Sends a buzz to your phone when Claude stops, a build finishes, or any terminal task completes — no polling needed").
				Value(&state.EnableNtfy),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("ntfy listen port").
				Description("Port for the notification server on your tailnet.\nDefault 2586 avoids conflicts with local dev servers (8080, 3000, etc.).").
				Value(&portStr).
				Validate(func(s string) error {
					n, err := strconv.Atoi(strings.TrimSpace(s))
					if err != nil || n < 1024 || n > 65535 {
						return fmt.Errorf("must be a number between 1024 and 65535")
					}
					return nil
				}),
		),
	)
	return form, nil
}

// StepVerify builds the doctor-run confirmation form (Stage 5). The form asks
// whether to run `abysslink doctor` now. The actual command is NOT invoked here.
func StepVerify(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	var runNow bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Run `abysslink doctor` now?").
				Description("Checks all modules for misconfigurations.").
				Affirmative("Yes, run it").
				Negative("No, I'll run it later").
				Value(&runNow),
		),
	)
	_ = state
	_ = runNow
	return form, nil
}

// StepACL builds the ACL-push confirmation form (Stage 6). The form asks
// whether to run `abysslink acl push --apply` now. The actual command is NOT
// invoked here.
func StepACL(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	var runNow bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Run `abysslink acl push --apply` now?").
				Description("Pushes the abysslink ACL to your tailnet. Requires OAuth config.").
				Affirmative("Yes, push ACL").
				Negative("No, I'll manage it manually").
				Value(&runNow),
		),
	)
	_ = state
	_ = runNow
	return form, nil
}

// StepDone signals the end of the setup wizard (Stage 7). It returns nil
// (no interactive form) — the caller renders a glamour summary panel and
// prints the completion message. Returning nil is the documented contract:
// callers must guard with `if form != nil`.
func StepDone(_ context.Context, _ shell.Runner, _ Printer, _ *FlowState) (*huh.Form, error) {
	return nil, nil
}
