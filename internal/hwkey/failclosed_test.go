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

package hwkey

// failclosed_test.go — the availability / no-fallback battery: every row of
// the fail-closed outcome table that refuses BEFORE any keygen exec.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errToolMissing = errors.New("executable file not found in $PATH")

// TestFIDO2Enroll_ToolAbsent: a missing ssh/ssh-keygen maps to ErrNotAvailable
// with no alternate tool tried and no key produced.
func TestFIDO2Enroll_ToolAbsent(t *testing.T) {
	r := shell.NewMockRunner()
	p := newTestFIDO2(r, Options{}, false, t.TempDir())
	p.resolvePath = func(string) (string, error) { return "", errToolMissing }

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
	require.ErrorIs(t, err, ErrNotAvailable)
	assert.Empty(t, r.RecordedCalls(), "no fallback exec after a missing tool")

	probe := p.Available(context.Background())
	assert.False(t, probe.OK)
}

// TestFIDO2Enroll_Exit255NoRetry: an interactive enrollment failure (exit 255
// — device not found, PIN x3, "Key enrollment failed: ...") is ErrEnrollFailed
// with EXACTLY ONE keygen invocation: never retried with a different -t and
// never retried without -w.
func TestFIDO2Enroll_Exit255NoRetry(t *testing.T) {
	r := shell.NewMockRunner(
		sshVOKCall(),
		shell.Call{Result: shell.Result{ExitCode: 255}}, // interactive keygen fails
	)
	p := newTestFIDO2(r, Options{}, false, t.TempDir())

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
	require.ErrorIs(t, err, ErrEnrollFailed)
	assert.NotErrorIs(t, err, ErrSoftwareKey, "an enrollment failure is never mapped to a software-key path")
	assert.Len(t, r.RunInteractiveCalls(), 1, "exactly one keygen invocation — no retry")
	assert.True(t, r.Done(), "no extra calls after the failure")
}

// TestFIDO2Available_DarwinNeedsProviderPath: stock Apple ssh-keygen has no
// USB middleware — without a configured sk-api dylib the provider is NOT
// available (and Enroll refuses; it never retries without -w).
func TestFIDO2Available_DarwinNeedsProviderPath(t *testing.T) {
	t.Run("unset_path", func(t *testing.T) {
		r := shell.NewMockRunner(sshVOKCall())
		p := newTestFIDO2(r, Options{}, true /* darwin semantics */, t.TempDir())
		probe := p.Available(context.Background())
		assert.False(t, probe.OK)
		assert.Contains(t, probe.Reason, "fido2_provider_path")
	})
	t.Run("missing_dylib", func(t *testing.T) {
		r := shell.NewMockRunner(sshVOKCall())
		p := newTestFIDO2(r, Options{FIDO2ProviderPath: filepath.Join(t.TempDir(), "absent.dylib")}, true, t.TempDir())
		probe := p.Available(context.Background())
		assert.False(t, probe.OK)
	})
	t.Run("enroll_refuses", func(t *testing.T) {
		r := shell.NewMockRunner(sshVOKCall())
		p := newTestFIDO2(r, Options{}, true, t.TempDir())
		_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
		require.ErrorIs(t, err, ErrNotAvailable)
		assert.Empty(t, r.RunInteractiveCalls(), "never runs keygen without -w on darwin")
	})
}

// TestAvailable_MixedToolchainDirsRefused: ssh and ssh-keygen from different
// directories (Apple + Homebrew mix) is refused — no "probably fine" path.
func TestAvailable_MixedToolchainDirsRefused(t *testing.T) {
	r := shell.NewMockRunner() // zero calls: the dirname compare refuses pre-exec
	p := newTestFIDO2(r, Options{}, false, t.TempDir())
	p.resolvePath = func(name string) (string, error) {
		if name == "ssh" {
			return "/usr/bin/ssh", nil
		}
		return "/opt/homebrew/bin/" + name, nil
	}

	probe := p.Available(context.Background())
	assert.False(t, probe.OK)
	assert.Contains(t, probe.Reason, "mixed ssh toolchain")

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
	require.ErrorIs(t, err, ErrNotAvailable)
	assert.Empty(t, r.RecordedCalls())
}

// TestAvailable_VersionFloor: OpenSSH below 10.0 is refused pre-exec
// (ErrVersionFloor); an unparseable/empty/non-zero `ssh -V` is ErrParse —
// never assume-modern.
func TestAvailable_VersionFloor(t *testing.T) {
	t.Run("below_floor", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stderr: "OpenSSH_9.9p1, LibreSSL 3.3.6\n", ExitCode: 0}})
		p := newTestFIDO2(r, Options{}, false, t.TempDir())
		_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
		require.ErrorIs(t, err, ErrVersionFloor)
		assert.Empty(t, r.RunInteractiveCalls(), "no keygen exec below the floor")
	})
	t.Run("unparseable_output", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stderr: "Fancy Custom SSH v99\n", ExitCode: 0}})
		p := newTestFIDO2(r, Options{}, false, t.TempDir())
		_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
		require.ErrorIs(t, err, ErrParse)
	})
	t.Run("empty_output", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
		p := newTestFIDO2(r, Options{}, false, t.TempDir())
		probe := p.Available(context.Background())
		assert.False(t, probe.OK)
	})
	t.Run("nonzero_exit", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stderr: "OpenSSH_10.0p1\n", ExitCode: 1}})
		p := newTestFIDO2(r, Options{}, false, t.TempDir())
		_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
		require.ErrorIs(t, err, ErrParse, "non-zero ssh -V never assumes a modern version")
	})
	t.Run("floor_reports_version", func(t *testing.T) {
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stderr: "OpenSSH_10.2p1, LibreSSL 3.3.6\n", ExitCode: 0}})
		p := newTestFIDO2(r, Options{}, false, t.TempDir())
		probe := p.Available(context.Background())
		assert.True(t, probe.OK)
		assert.Equal(t, "10.2", probe.SSHVersion)
	})
}

// TestNewProviderUnknownKind: the factory refuses unknown kinds (all GOOS).
func TestNewProviderUnknownKind(t *testing.T) {
	_, err := NewProvider(Kind("tarot-cards"), shell.NewMockRunner(), Options{})
	require.Error(t, err)
}

// TestSentinelErrorsAreDistinct guards errors.Is-based dispatch.
func TestSentinelErrorsAreDistinct(t *testing.T) {
	sentinels := []error{ErrNotAvailable, ErrNoTTY, ErrSoftwareKey, ErrEnrollFailed, ErrUnsupportedOS, ErrVersionFloor, ErrParse}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			assert.NotErrorIs(t, a, b)
		}
	}
	// Ensure os module errors are not confused with ours.
	assert.NotErrorIs(t, os.ErrNotExist, ErrNotAvailable)
}
