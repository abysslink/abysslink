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

// JourneyHeader with stage=3, total=7 must contain "Stage 3 of 7".
func TestJourneyHeader_StageText(t *testing.T) {
	labels := []string{"Account", "Prerequisites", "Converge", "Lock", "Enroll", "Verify", "Done"}
	out := tui.JourneyHeader(3, 7, labels)
	assert.Contains(t, out, "Stage 3 of 7", "JourneyHeader must display current stage / total")
}

// JourneyHeader must contain the stage label for the current stage.
func TestJourneyHeader_CurrentLabel(t *testing.T) {
	labels := []string{"Account", "Prerequisites", "Converge", "Lock", "Enroll", "Verify", "Done"}
	out := tui.JourneyHeader(3, 7, labels)
	assert.Contains(t, out, "Converge", "JourneyHeader must contain the label for the current stage")
}

// With NO_COLOR set, JourneyHeader output must not contain ANSI escapes.
func TestJourneyHeader_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	labels := []string{"Account", "Prerequisites", "Converge", "Lock", "Enroll", "Verify", "Done"}
	out := tui.JourneyHeader(3, 7, labels)
	assert.False(t, strings.Contains(out, "\x1b"), "NO_COLOR must suppress ANSI escape byte")
	// Stage text must still be present.
	assert.Contains(t, out, "Stage 3 of 7")
}

// JourneyHeader must contain "Abysslink Setup".
func TestJourneyHeader_Title(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	labels := []string{"A", "B", "C"}
	out := tui.JourneyHeader(1, 3, labels)
	assert.Contains(t, out, "Abysslink Setup")
}
