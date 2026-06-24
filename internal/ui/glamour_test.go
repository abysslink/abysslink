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

// Package ui_test contains stub tests for the glamour rendering helpers.
// All stubs except where noted are skipped until Wave 1 implements RenderMarkdown.
package ui_test

import (
	"testing"
)

// TestRenderMarkdown_StyledPath asserts that RenderMarkdown returns a styled
// (ANSI-coloured) string when the terminal supports colour (TUI-05, D-13, D-14).
// The styled output must come from glamour→string→Printer; no raw fmt.Println.
func TestRenderMarkdown_StyledPath(t *testing.T) {
	t.Skip("TODO: internal/ui.RenderMarkdown not yet implemented — Wave 1")
}

// TestRenderMarkdown_NoColor asserts that when NO_COLOR=1 is set, RenderMarkdown
// returns plain markdown without any ANSI escape sequences (TUI-05, D-13).
// The result must not contain the ESC byte (0x1b).
func TestRenderMarkdown_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Skip("TODO: internal/ui.RenderMarkdown not yet implemented — Wave 1")
}
