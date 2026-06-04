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
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureTailscaleAccount_HeadlessReturnsNil asserts that ensureTailscaleAccount
// with headless=true returns nil without opening /dev/tty or invoking any huh prompt.
// The informational signup-URL note must still be printed.
func TestEnsureTailscaleAccount_HeadlessReturnsNil(t *testing.T) {
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	runner := shell.NewMockRunner()
	err := ensureTailscaleAccount(p, runner, true)
	require.NoError(t, err)

	// Verify the informational signup-URL note is still printed in headless mode
	// so automated callers can log it.
	out := buf.String()
	require.True(t,
		strings.Contains(out, "https://login.tailscale.com/start"),
		"headless mode must still emit the signup URL; got: %q", out)
}

// TestEnsureTailscaleAccount_NonTTYStdinReturnsNil asserts that ensureTailscaleAccount
// with headless=false returns nil when stdin is not a TTY (the stdinIsTTY() gate).
// stdinIsTTY() returns false under go test (no TTY attached to the test process stdin).
func TestEnsureTailscaleAccount_NonTTYStdinReturnsNil(t *testing.T) {
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}
	runner := shell.NewMockRunner()

	// stdinIsTTY() returns false under go test (no TTY attached)
	err := ensureTailscaleAccount(p, runner, false)
	require.NoError(t, err)
}

// TestCheckACSleepDisabled covers the B3 regression: annotated pmset output
// (e.g. " sleep  0 (sleep prevented by powerd)") must be parsed correctly.
// Real macOS pmset -g emits lines with more than 2 fields — the old len==2 guard
// never matched those lines, causing sleep to never be detected as disabled.
func TestCheckACSleepDisabled(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"exact two fields", " sleep 0\n", true},
		{"annotated sleep 0", " sleep  0 (sleep prevented by powerd)\n", true},
		{"sleep enabled annotated", " sleep  1 (sleep prevented by caffeinate)\n", false},
		{"sleep key absent", " disksleep 0\n", false},
		{"empty output", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := shell.NewMockRunner(shell.Call{
				Result: shell.Result{Stdout: tt.output},
			})
			got := checkACSleepDisabled(context.Background(), runner)
			assert.Equal(t, tt.want, got, "pmset output: %q", tt.output)
		})
	}
}

// TestOpenURL_NoOpenerError asserts that openURL returns a non-nil error in the
// error path. Coverage strategy differs by platform:
//
//   - On macOS: "open" is always on PATH, so shell.LookPath("open") returns true
//     and openURL calls runner.Run. A zero-scripted MockRunner returns an
//     unexpected-call error, exercising the run-failure code path.
//   - On other platforms where neither "open" nor "xdg-open" is on PATH:
//     openURL returns "no browser opener found" before touching the runner.
//
// Both branches return a non-nil error — the test asserts require.Error in both.
func TestOpenURL_NoOpenerError(t *testing.T) {
	// Zero scripted calls — any subprocess invocation returns an error from MockRunner.
	runner := shell.NewMockRunner()

	err := openURL(runner, "https://example.com")
	require.Error(t, err, "openURL must return an error when opener absent or run fails")

	// On platforms where neither open nor xdg-open is on PATH, the error must
	// contain "no browser opener found". On macOS, the mock runner's unexpected-call
	// error is returned instead — both are non-nil which satisfies require.Error above.
	if !shell.LookPath("open") && !shell.LookPath("xdg-open") {
		assert.Contains(t, err.Error(), "no browser opener found",
			"no-opener error must contain expected message")
	}
}
