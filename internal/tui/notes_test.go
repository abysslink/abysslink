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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/abysslink/abysslink/internal/tui"
)

// Note at NoteDanger level must contain the word "DANGER" regardless of color.
// This satisfies the "color is never the only signal" requirement from §10.
func TestNote_DangerContainsWord(t *testing.T) {
	out := tui.Note(tui.NoteDanger, "Test Title", []string{"something bad"})
	assert.Contains(t, out, "DANGER", "NoteDanger output must contain the word DANGER")
}

// Note at NoteWarn level must contain the word "WARN".
func TestNote_WarnContainsWord(t *testing.T) {
	out := tui.Note(tui.NoteWarn, "Test Title", []string{"be careful"})
	assert.Contains(t, out, "WARN", "NoteWarn output must contain the word WARN")
}

// Note at NoteInfo level must contain the word "INFO".
func TestNote_InfoContainsWord(t *testing.T) {
	out := tui.Note(tui.NoteInfo, "Test Title", []string{"informational"})
	assert.Contains(t, out, "INFO", "NoteInfo output must contain the word INFO")
}

// Note at NoteSecurity level must contain the word "SECURITY".
func TestNote_SecurityContainsWord(t *testing.T) {
	out := tui.Note(tui.NoteSecurity, "Test Title", []string{"lock it down"})
	assert.Contains(t, out, "SECURITY", "NoteSecurity output must contain the word SECURITY")
}

// With NO_COLOR set, Note output must not contain ANSI escape byte 0x1b.
func TestNote_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	out := tui.Note(tui.NoteDanger, "Red Alert", []string{"critical issue"})
	assert.NotContains(t, string([]byte{0x1b}), out, "NO_COLOR must suppress ANSI escapes")
	assert.False(t, strings.Contains(out, "\x1b"), "NO_COLOR must suppress ANSI escape byte")
	// Word-level signal must still be present even without color.
	assert.Contains(t, out, "DANGER")
}

// Note includes the title and lines in the output.
func TestNote_IncludesTitleAndLines(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	out := tui.Note(tui.NoteInfo, "My Title", []string{"line one", "line two"})
	assert.Contains(t, out, "My Title")
	assert.Contains(t, out, "line one")
	assert.Contains(t, out, "line two")
}
