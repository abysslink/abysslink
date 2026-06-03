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
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/require"
)

// errProbeUnreachable is the deterministic ntfy-unreachable signal injected into
// the parity test so the golden never depends on whether a live ntfy service
// happens to be listening on localhost (see notify.HealthProbe).
var errProbeUnreachable = errors.New("parity: ntfy probe forced unreachable")

// noopRunner is a shell.Runner that returns a non-zero exit code (1) and no
// error for every command. It is used for the parity golden capture so that
// all shell-calling modules produce deterministic "not installed / unavailable"
// findings without executing any real subprocess.
//
// Returning ExitCode=1 (not an error) is the correct signal: modules that
// treat error-return as "daemon error" (e.g. lock detect) would propagate the
// error up and break cmd.Execute(). ExitCode=1 with nil error means "command
// ran but returned failure" — modules handle this with graceful findings.
type noopRunner struct{}

func (n *noopRunner) Run(_ context.Context, _ string, _ ...string) (shell.Result, error) {
	return shell.Result{ExitCode: 1}, nil
}

func (n *noopRunner) RunWithStdin(_ context.Context, _ io.Reader, _ string, _ ...string) (shell.Result, error) {
	return shell.Result{ExitCode: 1}, nil
}

func (n *noopRunner) RunInteractive(_ context.Context, _ string, _ ...string) error {
	return nil
}

func (n *noopRunner) RunWithEnv(_ context.Context, _ map[string]string, _ string, _ ...string) (shell.Result, error) {
	return shell.Result{ExitCode: 1}, nil
}

// TestUpDryRunParity captures the byte-for-byte `abysslink up --dry-run` output
// on the pre-refactor tree as a golden fixture (internal/cli/testdata/up_dryrun_v1.golden).
//
// First run: if the golden file is absent, the test writes buf.String() to it
// (capture mode). Subsequent runs assert buf.String() == golden (assert mode).
//
// This test is the regression guard for Phase 11 (BKND-05 / Pitfall 1): the
// golden MUST be committed before any internal/backend code is introduced.
//
// Isolation guarantees:
//   - NO_COLOR=1 strips all ANSI escape codes from lipgloss output.
//   - noopRunner (ExitCode=1, nil error) makes every shell-calling module
//     produce a deterministic "not installed / unavailable" finding without
//     touching the real system.
//   - XDG_STATE_HOME is redirected to t.TempDir() so audit log creation in
//     buildDeps does not write to the real home directory.
//   - newRunner is restored in t.Cleanup so it does not leak to other tests.
func TestUpDryRunParity(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	// CLICOLOR=0 suppresses any residual color paths not gated by NO_COLOR.
	t.Setenv("CLICOLOR", "0")

	// The golden is captured on darwin and the `up --dry-run` output is
	// platform-specific (e.g. ntfy installs via Docker Desktop on macOS but a
	// native package on Linux), so scope the assertion to darwin. The macOS CI
	// job exercises this guard; other platforms skip rather than diff a golden
	// that does not describe their install strategy.
	if runtime.GOOS != "darwin" {
		t.Skip("parity golden is darwin-scoped; up --dry-run output differs per-OS")
	}

	// Inject noopRunner; restore in Cleanup so other tests are unaffected.
	origNewRunner := newRunner
	newRunner = func() shell.Runner { return &noopRunner{} }
	t.Cleanup(func() { newRunner = origNewRunner })

	// Force the ntfy health probe to a deterministic "unreachable" result. The
	// probe is a live network dial that bypasses noopRunner, so without this the
	// golden would flip between "up to date" and "start ntfy service" depending
	// on whether a real ntfy service is listening on localhost (the historical
	// source of this test's flakiness). Restore in Cleanup.
	origProbe := notify.HealthProbe
	notify.HealthProbe = func(_ context.Context, _ string) error { return errProbeUnreachable }
	t.Cleanup(func() { notify.HealthProbe = origProbe })

	// Config path — relative to this test file's package directory.
	cfgPath := filepath.Join("testdata", "v1.yaml")

	// Execute `abysslink up --dry-run --config testdata/v1.yaml`.
	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs([]string{"up", "--dry-run", "--config", cfgPath})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	_ = cmd.Execute() // dry-run may return nil or a non-fatal error; capture either way

	got := buf.String()

	goldenPath := filepath.Join("testdata", "up_dryrun_v1.golden")

	if _, statErr := os.Stat(goldenPath); os.IsNotExist(statErr) {
		// First run: write the golden file.
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o750))
		require.NoError(t, os.WriteFile(goldenPath, []byte(got), 0o600),
			"failed to write golden file %s", goldenPath)
		t.Logf("golden captured at %s (%d bytes)", goldenPath, len(got))
		return
	}

	// Subsequent runs: assert output is byte-for-byte identical to the golden.
	golden, err := os.ReadFile(goldenPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	require.NoError(t, err)
	require.Equal(t, string(golden), got,
		"up --dry-run output differs from golden %s; "+
			"if the change is intentional, delete the golden and re-run to regenerate", goldenPath)
}
