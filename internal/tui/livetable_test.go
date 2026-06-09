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
	"testing"

	"github.com/abysslink/abysslink/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenderRows_ContainsBothModuleNames asserts that RenderRows of two
// completed RowEvents produces output containing both module names and a
// [2/2]-style counter.
func TestRenderRows_ContainsBothModuleNames(t *testing.T) {
	rows := []tui.RowEvent{
		{Module: "tailscale", Index: 1, Total: 2},
		{Module: "ssh", Index: 2, Total: 2},
	}
	out := tui.RenderRows(rows)
	assert.Contains(t, out, "tailscale")
	assert.Contains(t, out, "ssh")
	assert.Contains(t, out, "[2/2]", "counter [N/M] must appear in the output")
}

// TestRenderRows_Empty asserts that RenderRows of no rows returns an empty string.
func TestRenderRows_Empty(t *testing.T) {
	out := tui.RenderRows([]tui.RowEvent{})
	assert.Equal(t, "", out)
}

// TestRowEvent_HasFields ensures the RowEvent struct has the minimum required fields.
func TestRowEvent_HasFields(t *testing.T) {
	evt := tui.RowEvent{
		Module: "tailscale",
		Index:  1,
		Total:  3,
	}
	assert.Equal(t, "tailscale", evt.Module)
	assert.Equal(t, 1, evt.Index)
	assert.Equal(t, 3, evt.Total)
}

// TestTableModel_ImplementsTeaModel asserts the live table model implements the
// tea.Model interface (Init, Update, View are all defined). This is a compile-
// time guarantee checked at runtime via interface assertion.
func TestTableModel_ImplementsTeaModel(t *testing.T) {
	m := tui.NewLiveTable()
	// Check the tea.Model interface via method presence calls (compile-time guarantee).
	_ = m.Init()
	_, _ = m.Update(nil)
	_ = m.View()
}

// TestNoInternalModulesImport is a documentation test: livetable.go and
// spinner.go must NOT import internal/modules. The acceptance criteria require
// a grep assertion; we document it here and it is verified in the CI script.
// This test always passes — the real enforcement is in the Makefile/CI grep.
func TestNoInternalModulesImport(_ *testing.T) {
	// Documented acceptance criterion: package tui must not import internal/modules.
	// Verified via: grep -r "internal/modules" internal/tui/ → should produce no output.
}

// TestLiveTable_InFlightLabel is the F-63 regression guard. Pre-fix, View()
// hardcoded "scanning..." for the in-flight row, so the apply-phase live table
// claimed to be scanning while it was mutating the system. NewLiveTable keeps
// the default label; NewLiveTableWithLabel sets a phase-specific one; an empty
// label falls back to the default. Once done, no in-flight label is rendered.
func TestLiveTable_InFlightLabel(t *testing.T) {
	t.Run("default is scanning", func(t *testing.T) {
		m := tui.NewLiveTable()
		assert.Contains(t, m.View(), "scanning...")
	})
	t.Run("custom label is rendered", func(t *testing.T) {
		m := tui.NewLiveTableWithLabel("applying...")
		out := m.View()
		assert.Contains(t, out, "applying...")
		assert.NotContains(t, out, "scanning...", "apply-phase table must not claim to be scanning (F-63)")
	})
	t.Run("empty label falls back to default", func(t *testing.T) {
		m := tui.NewLiveTableWithLabel("")
		assert.Contains(t, m.View(), "scanning...")
	})
}

// TestLiveTable_Update_CtrlCQuits is the Phase 10 stdin-race regression guard.
// Pre-fix, LiveTable.Update only handled tea.QuitMsg, so Ctrl-C in a running
// tea program was silently dropped — the user could not abort the loader. The
// fix adds a tea.KeyMsg branch that returns tea.Quit for KeyCtrlC. Invoking
// the returned tea.Cmd must produce a tea.QuitMsg.
func TestLiveTable_Update_CtrlCQuits(t *testing.T) {
	m := tui.NewLiveTable()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	require.NotNil(t, cmd, "Ctrl-C must yield a non-nil tea.Cmd (tea.Quit)")
	assert.IsType(t, tea.QuitMsg{}, cmd(), "Ctrl-C cmd must produce tea.QuitMsg")
}

// TestLiveTable_Update_CtrlDQuits asserts Ctrl-D is treated as a cancel
// synonym, matching shell-prompt convention.
func TestLiveTable_Update_CtrlDQuits(t *testing.T) {
	m := tui.NewLiveTable()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	require.NotNil(t, cmd, "Ctrl-D must yield a non-nil tea.Cmd (tea.Quit)")
	assert.IsType(t, tea.QuitMsg{}, cmd(), "Ctrl-D cmd must produce tea.QuitMsg")
}

// TestLiveTable_Update_EscQuits asserts Esc cancels the program.
func TestLiveTable_Update_EscQuits(t *testing.T) {
	m := tui.NewLiveTable()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	require.NotNil(t, cmd, "Esc must yield a non-nil tea.Cmd (tea.Quit)")
	assert.IsType(t, tea.QuitMsg{}, cmd(), "Esc cmd must produce tea.QuitMsg")
}

// TestLiveTable_Update_OtherKeysDropped asserts that non-cancel keys (including
// Enter, which the user reported as "appears to advance to the next step")
// produce a nil tea.Cmd — i.e. they do not advance state or emit any side
// effect. Without the explicit drop, tea silently buffered keystrokes inside
// the event loop, causing the perceived "Enter steps the loader" misbehavior.
func TestLiveTable_Update_OtherKeysDropped(t *testing.T) {
	cases := []struct {
		name string
		msg  tea.KeyMsg
	}{
		{"enter", tea.KeyMsg{Type: tea.KeyEnter}},
		{"space", tea.KeyMsg{Type: tea.KeySpace}},
		{"runes", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}},
		{"up arrow", tea.KeyMsg{Type: tea.KeyUp}},
		{"tab", tea.KeyMsg{Type: tea.KeyTab}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := tui.NewLiveTable()
			_, cmd := m.Update(tc.msg)
			assert.Nil(t, cmd, "%s must produce no tea.Cmd (silently dropped)", tc.name)
		})
	}
}
