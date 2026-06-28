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
	"strings"

	"github.com/charmbracelet/huh"

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
//
// CONTRACT (post-audit 2026-06-25): the configuration is collected and written
// to abysslink.yaml by the pre-flow wizard in internal/cli (runInitPrework),
// which is the SINGLE source of configuration data. These step funcs are the
// post-config journey: they recap what was set up and tell the user the exact
// command to run for each remaining stage. They are INFORMATIONAL — none of
// them collects data and none of them silently runs a command. The previous
// design re-asked the same questions into a discarded FlowState and presented
// four "Run it now?" confirms whose answers were thrown away (a no-op that made
// users believe Tailnet Lock was enabled when it was not). Both defects are
// removed here: the stages read the already-collected FlowState and render a
// huh.Note with the next command to run.
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

// noteForm wraps a single informational huh.Note in a one-group form with a
// "Continue" affordance. The caller runs it with the Abyss theme; on Enter the
// journey advances to the next stage. Keeping every stage a non-nil *huh.Form
// (except StepDone) preserves the StepFunc contract the signature test asserts.
func noteForm(title, description string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title(title).
				Description(description).
				Next(true).
				NextLabel("Continue →"),
		),
	)
}

// orDefault returns v when non-empty, else fallback — used so the recap never
// renders a blank value when a field was not collected (e.g. resume with a
// partially-populated config).
func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// enabledModules returns the space-joined list of enabled module names for the
// Enroll recap, or "none" when no modules were enabled.
func enabledModules(state *FlowState) string {
	var mods []string
	if state.EnableSSH {
		mods = append(mods, "ssh")
	}
	if state.EnableTmux {
		mods = append(mods, "tmux")
	}
	if state.EnableMosh {
		mods = append(mods, "mosh")
	}
	if state.EnableNtfy {
		mods = append(mods, "ntfy")
	}
	if len(mods) == 0 {
		return "none"
	}
	return strings.Join(mods, ", ")
}

// StepAccount (Stage 0) recaps the backend and account identity that were
// collected and written during the pre-flow wizard.
func StepAccount(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	desc := fmt.Sprintf(
		"Backend:  %s\nAccount:  %s\n\nYour configuration has been written to abysslink.yaml. The next stages recap what was set up and the exact command to run for each remaining step.",
		orDefault(state.BackendType, "tailscale"),
		orDefault(state.Email, "(set in abysslink.yaml)"),
	)
	return noteForm("Account", desc), nil
}

// StepPrereqs (Stage 1) recaps the rig hostname.
func StepPrereqs(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	desc := fmt.Sprintf(
		"Rig hostname:  %s\n\nThis is the tailnet name you will connect to from your phone.",
		orDefault(state.Hostname, "(set in abysslink.yaml)"),
	)
	return noteForm("Prerequisites", desc), nil
}

// StepConverge (Stage 2) directs the user to converge the system. It does NOT
// run the command itself — running `abysslink up --apply` is a separate,
// fully-tested command with its own --dry-run/--apply gating and live progress.
func StepConverge(_ context.Context, _ shell.Runner, _ Printer, _ *FlowState) (*huh.Form, error) {
	desc := "Next, converge your system to match abysslink.yaml:\n\n    abysslink up --apply\n\nThis applies every enabled module. It is dry-run by default — `--apply` executes the plan after showing it."
	return noteForm("Converge", desc), nil
}

// StepLock (Stage 3) directs the user to enable Tailnet Lock. The disablement
// secrets are shown ONCE by `lock init --apply` and never stored — the security
// framing is preserved here so the user knows to have a password manager ready.
func StepLock(_ context.Context, _ shell.Runner, _ Printer, _ *FlowState) (*huh.Form, error) {
	desc := "Next, enable Tailnet Lock:\n\n    abysslink lock init --apply\n\nSECURITY: the disablement secrets are printed ONCE and never stored on disk. Have a password manager ready before you run it — losing them can permanently lock you out of your tailnet."
	return noteForm("Tailnet Lock", desc), nil
}

// StepEnroll (Stage 4) recaps the enabled modules and points at phone pairing.
func StepEnroll(_ context.Context, _ shell.Runner, _ Printer, state *FlowState) (*huh.Form, error) {
	desc := fmt.Sprintf(
		"Enabled modules:  %s\n\nPair your phone to this rig:\n\n    abysslink enroll phone",
		enabledModules(state),
	)
	return noteForm("Enroll", desc), nil
}

// StepVerify (Stage 5) directs the user to run the health check.
func StepVerify(_ context.Context, _ shell.Runner, _ Printer, _ *FlowState) (*huh.Form, error) {
	desc := "Next, verify every module is healthy:\n\n    abysslink doctor\n\nIt checks the configuration Abysslink manages and prints fix guidance for anything misconfigured."
	return noteForm("Verify", desc), nil
}

// StepACL (Stage 6) directs the user to push the access-control policy.
func StepACL(_ context.Context, _ shell.Runner, _ Printer, _ *FlowState) (*huh.Form, error) {
	desc := "Finally, apply the abysslink access policy to your tailnet:\n\n    abysslink acl push --apply\n\nRequires OAuth config for self-hosted backends. Dry-run by default."
	return noteForm("ACL", desc), nil
}

// StepDone signals the end of the setup wizard (Stage 7). It returns nil
// (no interactive form) — the caller renders a glamour summary panel and
// prints the completion message. Returning nil is the documented contract:
// callers must guard with `if form != nil`.
func StepDone(_ context.Context, _ shell.Runner, _ Printer, _ *FlowState) (*huh.Form, error) {
	return nil, nil
}
