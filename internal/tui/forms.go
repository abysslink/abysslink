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

	"github.com/charmbracelet/huh"
)

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
	if err := form.RunWithContext(ctx); err != nil {
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
	if err := form.RunWithContext(ctx); err != nil {
		return "", err
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
	if err := form.RunWithContext(ctx); err != nil {
		return "", err
	}
	return result, nil
}
