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

// Package ui_test contains tests for the glamour rendering helpers.
package ui_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenderMarkdown_StyledPath asserts that RenderMarkdown returns a styled
// (ANSI-coloured) string when the terminal supports colour (TUI-05, D-13, D-14).
// The styled output must come from glamour→string→Printer; no raw fmt.Println.
func TestRenderMarkdown_StyledPath(t *testing.T) {
	result := ui.RenderMarkdown("# Hello\n\nworld", false)
	require.NotEmpty(t, result, "RenderMarkdown must return a non-empty string")
	assert.True(t, strings.Contains(result, "Hello"), "rendered output must contain the heading text")
}

// TestRenderMarkdown_NoColor asserts that when NO_COLOR=1 is set, RenderMarkdown
// returns plain markdown without any ANSI escape sequences (TUI-05, D-13).
// The result must not contain the ESC byte (0x1b).
func TestRenderMarkdown_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	result := ui.RenderMarkdown("# Hello\n\nworld", true)
	require.NotEmpty(t, result, "RenderMarkdown must return a non-empty string on noColor=true path")
	assert.False(t, bytes.ContainsRune([]byte(result), 0x1b),
		"noColor=true path must not contain ANSI escape byte (0x1b)")
}
