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
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
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
