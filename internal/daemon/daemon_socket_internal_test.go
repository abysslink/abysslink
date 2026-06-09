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

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NET-13 regression tests: the macOS/no-XDG socket-dir fallback lives under
// the world-writable OS temp dir; ensurePrivateDir must fail closed on any
// pre-created path a local attacker could control (symlink, wrong mode, not a
// directory). Ownership-mismatch cannot be exercised without root, but the
// uid check shares the same Lstat code path verified here.

func TestEnsurePrivateDir_CreatesFresh(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "abl-sock")
	require.NoError(t, ensurePrivateDir(dir))

	fi, err := os.Lstat(dir)
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}

func TestEnsurePrivateDir_RejectsSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(real, 0o700))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(real, link))

	err := ensurePrivateDir(link)
	require.Error(t, err, "a pre-created symlink must be rejected (NET-13)")
	assert.Contains(t, err.Error(), "symlink")
}

func TestEnsurePrivateDir_RejectsWrongMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose")
	require.NoError(t, os.Mkdir(dir, 0o755))
	// Umask-proof: force the loose mode explicitly.
	require.NoError(t, os.Chmod(dir, 0o755))

	err := ensurePrivateDir(dir)
	require.Error(t, err, "a pre-created dir with mode != 0700 must be rejected (NET-13)")
	assert.Contains(t, err.Error(), "0700")
}

func TestEnsurePrivateDir_RejectsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	err := ensurePrivateDir(path)
	require.Error(t, err, "a pre-created regular file must be rejected (NET-13)")
}

// TestSocketPath_FailsClosedOnBadFallbackDir verifies the public seam: when
// XDG_RUNTIME_DIR is unset and the temp-dir fallback fails verification,
// SocketPath returns "" (callers cannot bind or dial an empty path).
func TestSocketPath_FailsClosedOnBadFallbackDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)

	// Pre-create the fallback path as a symlink — the local-attacker squat.
	victim := filepath.Join(tmp, fmt.Sprintf("abysslink-%d", os.Getuid()))
	elsewhere := filepath.Join(tmp, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	require.NoError(t, os.Symlink(elsewhere, victim))

	assert.Empty(t, SocketPath(), "SocketPath must fail closed on a squatted fallback dir (NET-13)")
}

// TestSocketPath_FallbackHappyPath verifies the normal macOS/no-XDG path still
// resolves and creates a private 0700 directory.
func TestSocketPath_FallbackHappyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)

	p := SocketPath()
	require.NotEmpty(t, p)
	assert.Equal(t, "abysslinkd.sock", filepath.Base(p))

	fi, err := os.Lstat(filepath.Dir(p))
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}
