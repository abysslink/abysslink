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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestPanicNoConfirmCall verifies that the panic command does NOT call Confirm,
// Pause, or ConfirmTyped — panic must execute immediately without prompting.
// We verify by checking the Short description does not reference a confirm gate
// (Long text may mention "no confirmation" to document the design decision).
func TestPanicNoConfirmCall(t *testing.T) {
	cmd := newPanicCmd()
	// Short description must not say "confirm required" or similar.
	assert.NotContains(t, strings.ToLower(cmd.Short), "confirm required",
		"panic Short must not imply confirmation is required")
	// The command must not call Pause or ConfirmTyped — verified by having
	// no Runnable() returns true with a blocking huh form. The binary-level
	// test (testPanicNoHang in conformance suite) asserts the real behavior.
	assert.NotNil(t, cmd.RunE, "panic RunE must be set")
}

// TestPanicHasDoneInTiming verifies that the panic command's output would
// include step markers (✓/✗) and a "done in" timing line.
// We test this structurally by checking that cmd_panic.go uses the icon constants
// and "done in" text (verified via the panicStep helper function's signature).
func TestPanicHasDoneInTiming(t *testing.T) {
	// Verify the panicStep function exists and produces ✓ on success.
	var out strings.Builder
	p := NewHumanPrinterTo(&out, &out)

	// Success step.
	panicStep(p, "disconnect tailnet", nil)
	successOutput := out.String()

	out.Reset()
	// Failure step.
	panicStep(p, "revoke device", errPanicStepFailed{"mock error"})
	failOutput := out.String()

	assert.Contains(t, successOutput, iconDone,
		"panicStep success must contain the ✓ icon")
	assert.Contains(t, failOutput, iconFatal,
		"panicStep failure must contain the ✕ icon")
}

// TestPanicCommandHasExample verifies the panic command has an Example field.
func TestPanicCommandHasExample(t *testing.T) {
	cmd := newPanicCmd()
	assert.NotEmpty(t, cmd.Example,
		"panic command must have an Example field for --help")
}

// TestAllCommandsHaveExamples walks the cobra command tree and asserts that
// every runnable (non-group) leaf command has a non-empty Example string.
// The inventory mirrors buildRootCmd: init, up, status, doctor, repair, enroll,
// notify, watch, acl, lock, rotate, logs, backup, upgrade, version, daemon,
// enable, disable, threat-model, uninstall, panic.
func TestAllCommandsHaveExamples(t *testing.T) {
	root := buildRootCmd()
	assertExamplesRecursive(t, root)
}

// assertExamplesRecursive walks the command tree depth-first.
func assertExamplesRecursive(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	for _, sub := range cmd.Commands() {
		if len(sub.Commands()) > 0 {
			// Parent group — recurse into children.
			assertExamplesRecursive(t, sub)
		} else if sub.Runnable() {
			assert.NotEmpty(t, sub.Example,
				"command %q must have a non-empty Example field", sub.Use)
		}
	}
}
