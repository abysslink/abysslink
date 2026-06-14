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

package ssh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCAProvider is a test double for CAProvider. caErr, when non-nil, exercises
// the fail-safe path (CAPublicKey error → legacy drop-in, no directives).
type fakeCAProvider struct {
	caLine  string
	caErr   error
	serials []uint64
}

func (f fakeCAProvider) CAPublicKey(_ context.Context) (string, error) {
	return f.caLine, f.caErr
}

func (f fakeCAProvider) RevokedSerials() []uint64 { return f.serials }

// Compile-time assertion that the fake satisfies the interface.
var _ CAProvider = fakeCAProvider{}

// TestRenderKRLSpec pins the deterministic, sorted spec render: regardless of
// input order the output is sorted ascending and byte-identical across calls.
func TestRenderKRLSpec(t *testing.T) {
	cases := []struct {
		name string
		in   []uint64
		want string
	}{
		{
			name: "two_serials_unsorted",
			in:   []uint64{7, 5},
			want: krlSpecHeader + "serial: 5\nserial: 7\n",
		},
		{
			name: "already_sorted",
			in:   []uint64{1, 2, 3},
			want: krlSpecHeader + "serial: 1\nserial: 2\nserial: 3\n",
		},
		{
			name: "single",
			in:   []uint64{42},
			want: krlSpecHeader + "serial: 42\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderKRLSpec(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}

	// Determinism: the same unsorted input renders byte-identical output twice,
	// and renderKRLSpec must not mutate its input slice.
	in := []uint64{9, 3, 6, 1}
	first := renderKRLSpec(in)
	second := renderKRLSpec(in)
	assert.Equal(t, first, second, "renderKRLSpec must be the deterministic idempotency anchor")
	assert.Equal(t, []uint64{9, 3, 6, 1}, in, "renderKRLSpec must not mutate its input")
	assert.Equal(t, krlSpecHeader+"serial: 1\nserial: 3\nserial: 6\nserial: 9\n", first)
}

// TestEmptyKRLSpec asserts nil and empty slices both yield the header alone —
// a valid empty spec (yielding a valid empty KRL revoking nothing).
func TestEmptyKRLSpec(t *testing.T) {
	for _, in := range [][]uint64{nil, {}} {
		got := renderKRLSpec(in)
		require.Equal(t, krlSpecHeader, got, "empty serial set must render the header alone")
		assert.Equal(t, 0, strings.Count(got, "serial:"), "empty spec must contain no serial lines")
	}
}

// recordingAudit wraps a real audit.Audit so staged files actually land on disk
// (the idempotency read-back relies on the persisted spec/KRL) while recording
// every WriteFile path+perm for assertions — mirroring the device-store fakes.
type recordingAudit struct {
	*audit.Audit
	writes []recordedWrite
}

type recordedWrite struct {
	path string
	perm os.FileMode
}

func (r *recordingAudit) WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error {
	r.writes = append(r.writes, recordedWrite{path: path, perm: perm})
	return r.Audit.WriteFile(path, content, perm, dryRun)
}

func (r *recordingAudit) hasWrite(suffix string) bool {
	for _, w := range r.writes {
		if strings.HasSuffix(w.path, suffix) {
			return true
		}
	}
	return false
}

// newKRLModule builds an ssh module with HOME pointed at a temp dir and a
// recording audit writer wrapping a real on-disk audit log.
func newKRLModule(t *testing.T, r shell.Runner) (*Module, *recordingAudit) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	ra := &recordingAudit{Audit: audit.New(filepath.Join(dir, "audit.log"))}
	cfg := config.Defaults()
	cfg.Modules.SSH.Enabled = true
	cfg.Modules.SSH.Mode = "openssh-fallback"
	cfg.Identity.UnixUser = "alice"
	m := New(modules.Deps{Cfg: cfg, Runner: r, Audit: ra})
	return m, ra
}

// stagedPath returns the staged path under the temp HOME's generated dir.
func stagedPath(t *testing.T, name string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	return filepath.Join(home, ".config", "abysslink", "generated", name)
}

// TestParseKRLSerials covers the range-aware decode of `ssh-keygen -Q -l -f`
// output. ssh-keygen collapses consecutive serials into "serial: N-M" ranges
// (the common case, since device serials are monotonic), so the parser must
// expand them; a non-numeric/inverted serial line is an error (never a silent
// drop that would mis-report drift).
func TestParseKRLSerials(t *testing.T) {
	got, err := ParseKRLSerials("# CA key ssh-ed25519 SHA256:abc\n  serial: 1-3 \nserial: 7-8\nserial: 20\nnoise\n")
	require.NoError(t, err)
	assert.Equal(t, []uint64{1, 2, 3, 7, 8, 20}, got, "ranges expanded, header+noise ignored, sorted+deduped")

	single, err := ParseKRLSerials("serial: 7\nserial: 5\nserial: 5\n")
	require.NoError(t, err)
	assert.Equal(t, []uint64{5, 7}, single, "single serials deduped + sorted")

	empty, err := ParseKRLSerials("# CA key only\n")
	require.NoError(t, err)
	assert.Empty(t, empty, "header-only ⇒ empty set (valid empty KRL)")

	_, err = ParseKRLSerials("serial: not-a-number\n")
	require.Error(t, err, "non-numeric serial must error, never silently drop")
	_, err = ParseKRLSerials("serial: 9-2\n")
	require.Error(t, err, "inverted range must error")
}

// TestKRLBuildArgv asserts buildAndStageKRL invokes ssh-keygen through the
// Runner with -k -f <krl> -s <ca.pub> <spec-input> (the -s flag is present and
// the spec input is the final operand), then re-decodes the KRL with -Q -l to
// verify the serial set, and audit-writes the CA pub, spec input, KRL, and the
// spec anchor.
func TestKRLBuildArgv(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}},                                         // ssh-keygen -k
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "# CA\nserial: 5\nserial: 7\n"}}, // ssh-keygen -Q -l (assertKRLSerials)
	)
	m, ra := newKRLModule(t, r)

	// MockRunner has no side-effect hook: pre-create the stub KRL the helper
	// reads back after ssh-keygen "writes" it.
	require.NoError(t, os.MkdirAll(filepath.Dir(stagedPath(t, stagedKRLName)), 0o700))
	require.NoError(t, os.WriteFile(stagedPath(t, stagedKRLName), []byte("KRL-STUB"), 0o644))

	changed, err := m.buildAndStageKRL(context.Background(), "ssh-ed25519 AAAACA test-ca", []uint64{7, 5})
	require.NoError(t, err)
	assert.True(t, changed)

	calls := r.RecordedCalls()
	require.Len(t, calls, 2, "ssh-keygen -k then ssh-keygen -Q -l (serial-set verify)")
	assert.Equal(t, "ssh-keygen", calls[0].Name)
	args := calls[0].Args
	require.GreaterOrEqual(t, len(args), 6)
	assert.Equal(t, "-k", args[0])
	assert.Equal(t, "-f", args[1])
	assert.Equal(t, "-s", args[3], "-s <ca.pub> is required for by-serial revocation")
	assert.True(t, strings.HasSuffix(args[4], stagedCAName), "-s operand is the staged CA pub")
	assert.True(t, strings.HasSuffix(args[len(args)-1], ".spec.in"), "the spec INPUT path is the final operand (not the anchor)")
	assert.Equal(t, []string{"-Q", "-l", "-f"}, calls[1].Args[:3], "second call decodes the KRL for the serial-set check")

	assert.True(t, ra.hasWrite(stagedCAName), "CA pub must be audit-written")
	assert.True(t, ra.hasWrite(stagedSpecName), "spec anchor must be audit-written")
	assert.True(t, ra.hasWrite(stagedKRLName), "KRL must be re-staged through audit")
}

// TestKRLIdempotent asserts a second build over the same serial set is skipped:
// changed=false and NO ssh-keygen call (idempotency on the spec, never on KRL
// bytes).
func TestKRLIdempotent(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}},                                         // ssh-keygen -k (first build)
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "# CA\nserial: 5\nserial: 7\n"}}, // ssh-keygen -Q -l verify
	)
	m, _ := newKRLModule(t, r)

	require.NoError(t, os.MkdirAll(filepath.Dir(stagedPath(t, stagedKRLName)), 0o700))
	require.NoError(t, os.WriteFile(stagedPath(t, stagedKRLName), []byte("KRL-STUB"), 0o644))

	serials := []uint64{5, 7}
	changed, err := m.buildAndStageKRL(context.Background(), "ssh-ed25519 AAAACA test-ca", serials)
	require.NoError(t, err)
	require.True(t, changed, "first build must run")
	require.True(t, r.Done(), "both scripted ssh-keygen calls must be consumed by the first build")

	// Second build over the unchanged serial set must NOT call ssh-keygen. A
	// fresh MockRunner with zero scripted calls would error on any Run.
	r2 := shell.NewMockRunner()
	m.runner = r2
	changed2, err2 := m.buildAndStageKRL(context.Background(), "ssh-ed25519 AAAACA test-ca", serials)
	require.NoError(t, err2)
	assert.False(t, changed2, "unchanged serial set must be a no-op (spec dedup)")
	assert.True(t, r2.Done(), "no ssh-keygen call may be issued on the idempotent path")
}

// TestKRLBuildFailureStagesNoKRL asserts a non-zero ssh-keygen exit aborts with
// a wrapped error, stages no KRL, and — critically — does NOT advance the spec
// anchor (M1: a mid-build failure must never leave the anchor ahead of its KRL,
// which would make the next run dedup-skip and install a stale KRL).
func TestKRLBuildFailureStagesNoKRL(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 255, Stderr: "requires specification of a CA key"}},
	)
	m, ra := newKRLModule(t, r)

	changed, err := m.buildAndStageKRL(context.Background(), "ssh-ed25519 AAAACA test-ca", []uint64{5})
	require.Error(t, err)
	assert.False(t, changed)
	assert.Contains(t, err.Error(), "ssh-keygen -k exited 255")
	assert.False(t, ra.hasWrite(stagedKRLName), "no KRL may be staged on build failure")
	// The anchor (stagedSpecName) must NOT exist on disk after a failed build.
	_, statErr := os.Stat(stagedPath(t, stagedSpecName))
	assert.True(t, os.IsNotExist(statErr), "spec anchor must not be advanced when the build fails (M1)")
}

// TestKRLSerialMismatchRefuses asserts the serial-set verification (M2) aborts
// when the built KRL does not revoke exactly the desired serials — and does not
// advance the anchor — so a well-formed-but-wrong KRL can never install.
func TestKRLSerialMismatchRefuses(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}},                        // ssh-keygen -k
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "serial: 5\n"}}, // -Q -l reports ONLY 5
	)
	m, ra := newKRLModule(t, r)
	require.NoError(t, os.MkdirAll(filepath.Dir(stagedPath(t, stagedKRLName)), 0o700))
	require.NoError(t, os.WriteFile(stagedPath(t, stagedKRLName), []byte("KRL-STUB"), 0o644))

	changed, err := m.buildAndStageKRL(context.Background(), "ssh-ed25519 AAAACA test-ca", []uint64{5, 9})
	require.Error(t, err, "KRL revoking {5} but store wants {5,9} must be refused")
	assert.False(t, changed)
	assert.Contains(t, err.Error(), "refusing to install")
	_, statErr := os.Stat(stagedPath(t, stagedSpecName))
	assert.True(t, os.IsNotExist(statErr), "anchor must not advance on a serial-set mismatch")
	_ = ra
}
