//go:build darwin

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

package darwin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privArgv prefixes sudo iff the test process is not root, mirroring
// runPrivileged so assertions hold whether CI runs as root or not.
func privArgv(name string, args ...string) []string {
	argv := append([]string{name}, args...)
	if os.Geteuid() != 0 {
		argv = append([]string{"sudo"}, argv...)
	}
	return argv
}

// redirectSystemPathDir points systemPathDir at a temp dir for the test.
func redirectSystemPathDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := systemPathDir
	systemPathDir = dir
	t.Cleanup(func() { systemPathDir = orig })
	return dir
}

func TestSymlinkIntoSystemPath_CreatesLink(t *testing.T) {
	dir := redirectSystemPathDir(t)
	target := "/opt/homebrew/bin/mosh-server"
	r := shell.NewMockRunner(shell.Call{}, shell.Call{}) // mkdir, ln
	p := New(r)

	require.NoError(t, p.SymlinkIntoSystemPath(context.Background(), target))

	link := filepath.Join(dir, "mosh-server")
	assert.Equal(t, [][]string{
		privArgv("mkdir", "-p", dir),
		privArgv("ln", "-sf", target, link),
	}, r.RunCalls())
}

func TestSymlinkIntoSystemPath_AlreadyLinked_NoOp(t *testing.T) {
	dir := redirectSystemPathDir(t)
	const target = "/opt/homebrew/bin/mosh-server"
	// The link name is the base of the target; point it at target already.
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "mosh-server")))

	r := shell.NewMockRunner() // zero scripted calls — any privileged op would error
	p := New(r)

	require.NoError(t, p.SymlinkIntoSystemPath(context.Background(), target))
	assert.Empty(t, r.RunCalls(), "already-correct link must not re-run mkdir/ln")
}

func TestIsOnSystemPath(t *testing.T) {
	dir := redirectSystemPathDir(t)
	p := New(shell.NewMockRunner())

	on, err := p.IsOnSystemPath(context.Background(), "mosh-server")
	require.NoError(t, err)
	assert.False(t, on, "absent binary is not on PATH")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "mosh-server"), []byte("x"), 0o755)) //nolint:gosec // test fixture
	on, err = p.IsOnSystemPath(context.Background(), "mosh-server")
	require.NoError(t, err)
	assert.True(t, on, "present binary is on PATH")
}

func TestDarwinFirewall_AllowApp(t *testing.T) {
	const bin = "/opt/homebrew/bin/mosh-server"
	r := shell.NewMockRunner(shell.Call{}, shell.Call{}) // --add, --unblockapp
	fw, ok := New(r).Firewall().(platform.AppFirewall)
	require.True(t, ok, "darwin firewall must implement AppFirewall")

	require.NoError(t, fw.AllowApp(context.Background(), bin))
	assert.Equal(t, [][]string{
		privArgv(fwBin, "--add", bin),
		privArgv(fwBin, "--unblockapp", bin),
	}, r.RunCalls())
}

func TestDarwinFirewall_IsAppAllowed(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{"permitted", "Incoming connection to /opt/homebrew/bin/mosh-server is permitted.", true},
		{"blocked", "Incoming connection to /opt/homebrew/bin/mosh-server is blocked.", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: tc.out}})
			fw := New(r).Firewall().(platform.AppFirewall)
			got, err := fw.IsAppAllowed(context.Background(), "/opt/homebrew/bin/mosh-server")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			// --getappblocked is read-only — no sudo.
			assert.Equal(t, [][]string{{fwBin, "--getappblocked", "/opt/homebrew/bin/mosh-server"}}, r.RunCalls())
		})
	}
}
