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
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlushManualSteps_NonInteractivePrintsAndClears is the F-59 guard for the
// CLI side: in a non-interactive context (--yes here; tests are never a TTY
// anyway) flushManualSteps must not block, must print the step body via the
// Printer, must not exec anything (no openURL), and must clear the collected
// slice so a second flush is a no-op.
func TestFlushManualSteps_NonInteractivePrintsAndClears(t *testing.T) {
	r := shell.NewMockRunner() // zero scripted calls: any exec would error the runner
	steps := []modules.ManualStep{{
		Title:   "ACL manual step",
		Body:    "paste the ACL into the admin editor\nURL: https://login.tailscale.com/admin/acls/file",
		URL:     "https://login.tailscale.com/admin/acls/file",
		Confirm: "press enter once saved",
	}}
	cc := &cmdContext{
		cfg:         config.Defaults(),
		runner:      r,
		yes:         true,
		manualSteps: &steps,
	}

	var out, errBuf bytes.Buffer
	p := NewHumanPrinterTo(&out, &errBuf)

	done := make(chan error, 1)
	go func() { done <- flushManualSteps(context.Background(), cc, p) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("flushManualSteps blocked in a non-interactive context — it must never prompt without a TTY")
	}

	assert.Contains(t, out.String(), "paste the ACL into the admin editor",
		"non-interactive flush must surface the instruction body via the Printer")
	assert.Empty(t, *cc.manualSteps, "flushed steps must be cleared")
	assert.Empty(t, r.RecordedCalls(), "non-interactive flush must not exec (no browser open)")

	// Second flush is a no-op.
	out.Reset()
	require.NoError(t, flushManualSteps(context.Background(), cc, p))
	assert.Empty(t, out.String(), "re-flush must not repeat already-flushed steps")
}

// TestFlushManualSteps_JSONModeKeepsStdoutClean asserts that under --json the
// step is reported via slog (stderr), never on the machine-readable stdout.
func TestFlushManualSteps_JSONModeKeepsStdoutClean(t *testing.T) {
	steps := []modules.ManualStep{{Title: "ACL manual step", Body: "do the thing"}}
	cc := &cmdContext{
		cfg:         config.Defaults(),
		runner:      shell.NewMockRunner(),
		jsonOut:     true,
		manualSteps: &steps,
	}

	var out, errBuf bytes.Buffer
	p := NewJSONPrinterTo(&out, &errBuf)

	require.NoError(t, flushManualSteps(context.Background(), cc, p))
	assert.Empty(t, out.String(), "--json: manual steps must never pollute stdout")
	assert.Empty(t, *cc.manualSteps, "flushed steps must be cleared")
}

// TestFlushManualSteps_EmptyAndNilAreNoOps covers cmdContexts built directly in
// tests (nil collector) and the common no-steps case.
func TestFlushManualSteps_EmptyAndNilAreNoOps(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := NewHumanPrinterTo(&out, &errBuf)

	require.NoError(t, flushManualSteps(context.Background(), &cmdContext{}, p))

	empty := []modules.ManualStep{}
	cc := &cmdContext{manualSteps: &empty, yes: true}
	require.NoError(t, flushManualSteps(context.Background(), cc, p))
	assert.Empty(t, out.String())
}

// TestBuildDeps_WiresDeferManualStep asserts the uniform path: buildDeps always
// sets Deps.DeferManualStep and the closure appends into cc.manualSteps, so
// modules always defer (never inline-prompt) when constructed by the CLI.
func TestBuildDeps_WiresDeferManualStep(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // avoid touching the real home dir

	cc := &cmdContext{cfg: config.Defaults(), runner: &shell.ExecRunner{}}
	deps, err := buildDeps(context.Background(), cc)
	require.NoError(t, err)

	require.NotNil(t, deps.DeferManualStep, "DeferManualStep must always be wired (uniform defer path, F-59)")
	require.NotNil(t, cc.manualSteps, "buildDeps must lazy-init the collector for directly-built cmdContexts")

	deps.DeferManualStep(modules.ManualStep{Title: "t", Body: "b"})
	require.Len(t, *cc.manualSteps, 1)
	assert.Equal(t, "t", (*cc.manualSteps)[0].Title)
}
