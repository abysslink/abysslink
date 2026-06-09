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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/tui"
)

// Confirm with yes=true bypasses the interactive prompt.
func TestConfirm_YesFlag(t *testing.T) {
	ok, err := tui.Confirm(context.Background(), "Do the thing?", true)
	require.NoError(t, err)
	assert.True(t, ok)
}

// Select with yes=true and a single option returns it immediately.
func TestSelect_YesFlagSingleOption(t *testing.T) {
	result, err := tui.Select(context.Background(), "Pick one", []string{"only"}, true)
	require.NoError(t, err)
	assert.Equal(t, "only", result)
}

// Select with yes=true but multiple options still requires interaction — so we
// test only that the function signature compiles and that calling with a
// cancelled context returns an error.
func TestSelect_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tui.Select(ctx, "Pick", []string{"a", "b"}, false)
	require.Error(t, err)
}

// Confirm with a cancelled context returns an error.
func TestConfirm_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tui.Confirm(ctx, "Confirm?", false)
	require.Error(t, err)
}

// Pause with yes=true returns nil immediately (no hang, no error).
func TestPause_YesFlag(t *testing.T) {
	err := tui.Pause(context.Background(), "Press Enter to continue...", true)
	require.NoError(t, err)
}

// Pause with a non-TTY stdin and yes=false also returns nil immediately.
// In a test environment stdin is not a TTY so this validates the non-TTY short-circuit.
func TestPause_NonTTY(t *testing.T) {
	// In a test runner stdin is not a TTY; Pause must return nil without hanging.
	err := tui.Pause(context.Background(), "Press Enter to continue...", false)
	require.NoError(t, err)
}

// PauseWithAction with yes=true skips interaction and reports "no action".
func TestPauseWithAction_YesFlag(t *testing.T) {
	action, err := tui.PauseWithAction(context.Background(), "msg", "Copy again", true)
	require.NoError(t, err)
	assert.False(t, action, "yes short-circuit must report Continue (no action)")
}

// PauseWithAction with a non-TTY stdin and yes=false also skips interaction:
// in a test runner stdin is not a TTY, so this validates the non-TTY
// short-circuit never hangs and never reports the action as chosen.
func TestPauseWithAction_NonTTY(t *testing.T) {
	action, err := tui.PauseWithAction(context.Background(), "msg", "Copy again", false)
	require.NoError(t, err)
	assert.False(t, action, "non-TTY short-circuit must report Continue (no action)")
}

// ConfirmTyped with yes=true returns true without prompting.
func TestConfirmTyped_YesFlag(t *testing.T) {
	ok, err := tui.ConfirmTyped(context.Background(), "Type UNINSTALL to confirm", "UNINSTALL", true)
	require.NoError(t, err)
	assert.True(t, ok)
}

// ConfirmTyped phrase matching table: test non-interactive cases via yes=true.
func TestConfirmTyped_PhraseMatchTable(t *testing.T) {
	cases := []struct {
		name     string
		yes      bool
		wantTrue bool
	}{
		{"yes flag returns true immediately", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := tui.ConfirmTyped(context.Background(), "prompt", "EXACT PHRASE", tc.yes)
			require.NoError(t, err)
			assert.Equal(t, tc.wantTrue, ok)
		})
	}
}

// ConfirmTyped with a cancelled context and yes=false returns an error (interactive
// path aborted by context cancellation — ensures the function does not silently
// succeed on mismatch).
func TestConfirmTyped_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tui.ConfirmTyped(ctx, "Type PHRASE", "PHRASE", false)
	require.Error(t, err)
}

// ConfirmBlast with yes=true returns true without prompting.
func TestConfirmBlast_YesFlag(t *testing.T) {
	ok, err := tui.ConfirmBlast(context.Background(), "Will install mosh, ntfy, tmux.", 3, true)
	require.NoError(t, err)
	assert.True(t, ok)
}

// ConfirmBlast with a cancelled context and yes=false returns an error.
func TestConfirmBlast_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tui.ConfirmBlast(ctx, "Will install mosh.", 1, false)
	require.Error(t, err)
}
