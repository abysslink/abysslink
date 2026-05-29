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

package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestColorEnabled_NOCOLORDisables verifies that setting NO_COLOR disables color output.
func TestColorEnabled_NOCOLORDisables(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	// Also clear CLICOLOR so only NO_COLOR is the gate.
	t.Setenv("CLICOLOR", "")
	assert.False(t, colorEnabled(), "NO_COLOR set → colorEnabled must return false")
}

// TestColorEnabled_CLICOLORZeroDisables verifies that CLICOLOR=0 disables color output.
func TestColorEnabled_CLICOLORZeroDisables(t *testing.T) {
	t.Setenv("CLICOLOR", "0")
	// Unset NO_COLOR so only CLICOLOR is the gate.
	t.Setenv("NO_COLOR", "")
	assert.False(t, colorEnabled(), "CLICOLOR=0 → colorEnabled must return false")
}

// TestColorEnabled_NeitherSet verifies behavior when neither NO_COLOR nor CLICOLOR=0 is set.
// In test environments stdout is not a TTY, so color is still disabled.
func TestColorEnabled_NeitherSet(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	// In tests stdout is not a TTY — colorEnabled() should return false because
	// the TTY check fails even without the env-var gates.
	assert.False(t, colorEnabled(), "no TTY in test → colorEnabled must return false")
}

// TestInteractive_YesFlagDisables verifies --yes (autoConfirm) makes interactive return false.
func TestInteractive_YesFlagDisables(t *testing.T) {
	assert.False(t, interactive(true, false),
		"interactive(yes=true, json=false) must return false")
}

// TestInteractive_JSONFlagDisables verifies --json makes interactive return false.
func TestInteractive_JSONFlagDisables(t *testing.T) {
	assert.False(t, interactive(false, true),
		"interactive(yes=false, json=true) must return false")
}

// TestInteractive_BothFlagsDisables verifies both flags together still return false.
func TestInteractive_BothFlagsDisables(t *testing.T) {
	assert.False(t, interactive(true, true),
		"interactive(yes=true, json=true) must return false")
}

// TestInteractive_NonTTYDisables verifies that a non-TTY stdin disables interactive.
// In tests stdin is not a TTY, so interactive(false, false) should be false.
func TestInteractive_NonTTYDisables(t *testing.T) {
	assert.False(t, interactive(false, false),
		"non-TTY stdin → interactive must return false even without flags")
}

// TestErrMissingInput_NamesFlag verifies that errMissingInput includes the flag name.
func TestErrMissingInput_NamesFlag(t *testing.T) {
	err := errMissingInput("apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apply",
		"errMissingInput must name the flag in the error message")
}

// TestErrMissingInput_DescriptiveMessage verifies errMissingInput returns a helpful message.
func TestErrMissingInput_DescriptiveMessage(t *testing.T) {
	err := errMissingInput("yes")
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, strings.ToLower(msg), "non-interactive",
		"error should describe the non-interactive context")
}

// TestStdoutIsTTY_NotInTest verifies that stdout is not a TTY in test environments.
func TestStdoutIsTTY_NotInTest(t *testing.T) {
	// In automated test runs, stdout is a pipe, not a terminal.
	assert.False(t, stdoutIsTTY(),
		"stdout should not be a TTY in automated test environments")
}

// TestStdinIsTTY_NotInTest verifies that stdin is not a TTY in test environments.
func TestStdinIsTTY_NotInTest(t *testing.T) {
	// In automated test runs, stdin is a pipe, not a terminal.
	assert.False(t, stdinIsTTY(),
		"stdin should not be a TTY in automated test environments")
}

// TestAnimationEnabled_NotInTest verifies animation is disabled in test environments.
func TestAnimationEnabled_NotInTest(t *testing.T) {
	// Animation requires a TTY; tests run headless.
	assert.False(t, animationEnabled(false),
		"animation must be disabled when not a TTY")
}

// TestAnimationEnabled_JSONDisables verifies animation is disabled in JSON mode.
func TestAnimationEnabled_JSONDisables(t *testing.T) {
	assert.False(t, animationEnabled(true),
		"animation must be disabled in JSON mode")
}
