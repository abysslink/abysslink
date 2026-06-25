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

package tui

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"github.com/abysslink/abysslink/internal/ui"
)

// stdinIsTTY reports whether os.Stdin is an interactive terminal.
func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// Confirm displays an interactive yes/no prompt. If yes is true, the question
// is skipped and the function returns true immediately (--yes flag behaviour).
func Confirm(ctx context.Context, prompt string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}

	var result bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(prompt).
				Value(&result),
		),
	)
	if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil {
		return false, err
	}
	return result, nil
}

// Select displays a single-choice picker. If yes is true and there is exactly
// one option, it is returned without interaction.
func Select(ctx context.Context, title string, options []string, yes bool) (string, error) {
	if yes && len(options) == 1 {
		return options[0], nil
	}

	var result string
	opts := make([]huh.Option[string], len(options))
	for i, o := range options {
		opts[i] = huh.NewOption(o, o)
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(title).
				Options(opts...).
				Value(&result),
		),
	)
	if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil {
		return "", err
	}
	return result, nil
}

// Pause displays a "Press Enter to continue…" message and waits for the user
// to press Enter. If yes is true OR stdin is not a TTY (headless/CI), Pause
// returns nil immediately without any interaction so automated runs never hang.
func Pause(ctx context.Context, msg string, yes bool) error {
	if yes || !stdinIsTTY() {
		return nil
	}
	// Use a huh Note (non-interactive informational display) then a minimal
	// Confirm prompt with no actual choice — the user presses Enter to proceed.
	var dummy bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(msg),
			huh.NewConfirm().
				Title("Press Enter to continue…").
				Value(&dummy),
		),
	)
	if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil {
		return err
	}
	return nil
}

// PauseWithAction shows msg and lets the user either continue or trigger the
// named action. Returns true when the action was chosen. Skips interaction
// (returns false, nil) when yes is true or stdin is not a TTY, mirroring
// Pause's short-circuit so automated runs never hang.
func PauseWithAction(ctx context.Context, msg, actionLabel string, yes bool) (bool, error) {
	if yes || !stdinIsTTY() {
		return false, nil
	}
	var action bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(msg),
			huh.NewSelect[bool]().
				Options(
					huh.NewOption("Continue", false),
					huh.NewOption(actionLabel, true),
				).
				Value(&action),
		),
	)
	if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil {
		return false, err
	}
	return action, nil
}

// ConfirmTyped requires the user to type an exact phrase before proceeding.
// If yes is true, it returns true immediately (--yes flag bypass). Otherwise
// it prompts with an huh.NewInput, trims surrounding whitespace from the
// response, and returns true only on an exact case-sensitive match against
// phrase. A mismatch returns false (caller decides how to handle; no retry
// built in). Used for attestation gates such as "I HAVE PRINTED IT" and
// "UNINSTALL".
func ConfirmTyped(ctx context.Context, prompt, phrase string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	var typed string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(prompt).
				Description(fmt.Sprintf("Type exactly: %s", phrase)).
				Value(&typed),
		),
	)
	if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil {
		return false, err
	}
	return strings.TrimSpace(typed) == phrase, nil
}

// ConfirmBlast renders a change-count summary and asks the user to approve
// before a high-blast-radius operation proceeds. If yes is true, it returns
// true immediately. When stdin is not a TTY (pipe, CI) and yes is false, it
// fails with a clear error naming --yes instead of letting huh surface a raw
// terminal failure (U1) — a mutation must never be auto-approved by the mere
// absence of a terminal. Otherwise it shows the summary lines and
// "Apply N changes? This will modify your system." in a y/N huh.NewConfirm
// and returns the user's choice.
func ConfirmBlast(ctx context.Context, summary string, count int, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !stdinIsTTY() {
		return false, fmt.Errorf("non-interactive session: cannot confirm applying %d change(s) — re-run with --yes to approve", count)
	}
	var result bool
	title := fmt.Sprintf("Apply %d change(s)? This will modify your system.", count)
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(summary),
			huh.NewConfirm().
				Title(title).
				Value(&result),
		),
	)
	if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil {
		return false, err
	}
	return result, nil
}

// Input displays a free-text prompt. If defaultValue is non-empty it is shown
// as the placeholder.
func Input(ctx context.Context, title, defaultValue string) (string, error) {
	result := defaultValue
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(title).
				Value(&result),
		),
	)
	if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil {
		return "", err
	}
	return result, nil
}
