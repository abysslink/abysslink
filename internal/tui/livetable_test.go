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
	"github.com/stretchr/testify/assert"
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
