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

package tui_test

import (
	"context"
	"errors"
	"testing"

	"github.com/abysslink/abysslink/internal/tui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunSpinner_PlainRunsWork asserts that RunSpinner with animate=false calls
// work exactly once and returns its result without starting a Bubble Tea program.
func TestRunSpinner_PlainRunsWork(t *testing.T) {
	called := 0
	err := tui.RunSpinner(context.Background(), "scanning", func(_ context.Context) error {
		called++
		return nil
	}, false)
	require.NoError(t, err)
	assert.Equal(t, 1, called, "work must be called exactly once")
}

// TestRunSpinner_PlainPropagatesError asserts that RunSpinner propagates errors
// from work without wrapping.
func TestRunSpinner_PlainPropagatesError(t *testing.T) {
	sentinel := errors.New("work failed")
	err := tui.RunSpinner(context.Background(), "scanning", func(_ context.Context) error {
		return sentinel
	}, false)
	assert.ErrorIs(t, err, sentinel)
}

// TestRunSpinner_PlainContextCancelled asserts that context cancellation before
// work starts causes RunSpinner to return ctx.Err().
func TestRunSpinner_PlainContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := tui.RunSpinner(ctx, "scanning", func(_ context.Context) error {
		return nil
	}, false)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestPlainStatus_ReturnsLabel asserts that PlainStatus returns a string
// containing the label.
func TestPlainStatus_ReturnsLabel(t *testing.T) {
	out := tui.PlainStatus("my label")
	assert.Contains(t, out, "my label")
}

// TestSpinnerColor is a stub that will verify that newSpinnerModel uses
// ui.ColorAccent (the Abyss cyan) rather than the legacy lipgloss.Color("8")
// for the spinner frame colour (TUI-06). This stub is SKIP until Plan 35-02
// upgrades the spinner implementation.
func TestSpinnerColor(t *testing.T) {
	t.Skip("TODO: spinner color upgrade to ui.ColorAccent — implement in Plan 35-02")
}
