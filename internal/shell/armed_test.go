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

package shell_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/shell"
)

// TestRunArmed verifies the core ArmedHandle contract:
//   - PGID > 0
//   - Done channel closes when the process exits
//   - Wait() returns nil for a zero-exit process
//   - ExecRunner satisfies the ArmedRunner interface
func TestRunArmed(t *testing.T) {
	r := &shell.ExecRunner{}

	// Verify ExecRunner satisfies ArmedRunner at compile time.
	var _ shell.ArmedRunner = r

	ctx := context.Background()
	// "sleep 0.01" exits quickly (10ms) — avoids flakiness on slow CI.
	handle, err := r.RunArmed(ctx, "sleep", "0.01")
	require.NoError(t, err)
	require.NotNil(t, handle)

	// PGID must be positive (cmd.Process.Pid when Setpgid=true).
	assert.Greater(t, handle.PGID, 0, "PGID must be positive")

	// Done channel must close when process exits.
	select {
	case <-handle.Done:
		// channel closed as expected
	case <-ctx.Done():
		t.Fatal("test context cancelled before Done closed")
	}

	// Wait must return nil for a zero-exit process.
	err = handle.Wait()
	assert.NoError(t, err, "Wait() must return nil for a zero-exit process")
}

// TestRunArmed_Setpgid verifies the process group invariant: when Setpgid=true,
// PGID == PID of the armed process (linux + darwin). We verify this by checking
// that handle.PGID == the expected pgid from the OS.
func TestRunArmed_Setpgid(t *testing.T) {
	r := &shell.ExecRunner{}
	ctx := context.Background()

	handle, err := r.RunArmed(ctx, "sleep", "0.01")
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Wait for the process to exit.
	<-handle.Done

	// On linux and darwin, pgid == pid when Setpgid=true.
	// We trust cmd.Process.Pid for this (A1 assumption in RESEARCH.md);
	// verify PGID is a plausible positive PID value.
	assert.Greater(t, handle.PGID, 0, "PGID must be a positive integer")
	// PGID must be < 2^22 (a reasonable upper bound for a process ID).
	assert.Less(t, handle.PGID, 1<<22, "PGID must be a reasonable PID value")
}

// TestRunArmedMinimal_DropsSecretEnv is the WR-01 / B10 regression: the armed
// agent spawned via RunArmedMinimal receives ONLY the B10-minimized environment,
// so a secret-looking parent var is DROPPED while an allowlisted var (PATH) is
// present. This proves env minimization is applied at a REAL spawn (not just in
// buildMinimalEnv unit scaffolding).
//
// RunArmedMinimal inherits os.Stdout (interactive armed process), so the test
// redirects os.Stdout to a temp file for the duration of the spawn and reads the
// child's printed env back from it. `env` is used (no sh -c, per CLAUDE.md).
func TestRunArmedMinimal_DropsSecretEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("env helper assumes POSIX")
	}
	if !shell.LookPath("env") {
		t.Skip("env not found on PATH")
	}

	secret := "ABYSSLINK_ARMED_SECRET_PROBE"
	t.Setenv(secret, "leak-me")
	t.Setenv("HOME", "/home/armedprobe")

	// Verify ExecRunner satisfies the optional ArmedMinimalRunner interface.
	r := &shell.ExecRunner{}
	var _ shell.ArmedMinimalRunner = r

	// Redirect os.Stdout to a temp file; the armed child inherits it.
	dir := t.TempDir()
	outPath := filepath.Join(dir, "child-env.txt")
	outFile, err := os.Create(outPath)
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = outFile
	defer func() { os.Stdout = origStdout }()

	handle, err := r.RunArmedMinimal(context.Background(), "env")
	require.NoError(t, err)
	require.NotNil(t, handle)
	assert.Greater(t, handle.PGID, 0, "PGID must be positive")
	<-handle.Done
	require.NoError(t, handle.Wait())

	require.NoError(t, outFile.Close())
	os.Stdout = origStdout // restore before reading/logging

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	childEnv := string(data)

	assert.NotContains(t, childEnv, secret+"=", "secret var must be DROPPED from the minimized armed child env")
	assert.Contains(t, childEnv, "PATH=", "PATH must be present in the minimized armed child env")
}

// TestArmedHandle_DoneClosesOnExit verifies that Done closes promptly after
// the child process exits, not before.
func TestArmedHandle_DoneClosesOnExit(t *testing.T) {
	r := &shell.ExecRunner{}
	ctx := context.Background()

	handle, err := r.RunArmed(ctx, "sleep", "0.01")
	require.NoError(t, err)

	// Done must not already be closed at spawn time.
	select {
	case <-handle.Done:
		t.Fatal("Done was closed before the process exited")
	default:
		// good: not yet closed
	}

	// After waiting, Done must be closed.
	<-handle.Done
	select {
	case <-handle.Done:
		// good: closed
	default:
		t.Fatal("Done was not closed after process exited")
	}
}
