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

//go:build linux

package hardening

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// checkLUKS MockRunner tests (DOC-02 fail-closed + DOC-01 OK backfill)
// ---------------------------------------------------------------------------

// luksEncryptedJSON is a minimal valid lsblk JSON with a crypt ancestor for /home.
const luksEncryptedJSON = `{"blockdevices":[{"name":"sda","type":"disk","mountpoint":null,"children":[{"name":"sda1","type":"crypt","mountpoint":null,"children":[{"name":"dm-0","type":"lvm","mountpoint":"/"}]}]}]}`

// TestCheckLUKS_FatalOnExecError asserts checkLUKS returns a FATAL finding
// (not nil,nil) when lsblk fails to execute (DOC-02 / D-06).
func TestCheckLUKS_FatalOnExecError(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Err: fmt.Errorf("exec: lsblk not found")})
	m := &Module{runner: r}
	findings, err := checkLUKS(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "should return a FATAL finding when lsblk is unavailable")
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "luks" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "must have a 'luks' check finding")
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "disk-encryption state is UNKNOWN")
}

// TestCheckLUKS_FatalOnNonZeroExit asserts checkLUKS returns FATAL when lsblk
// exits non-zero (DOC-02 / D-06).
func TestCheckLUKS_FatalOnNonZeroExit(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "lsblk error"}})
	m := &Module{runner: r}
	findings, err := checkLUKS(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "luks" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "disk-encryption state is UNKNOWN")
}

// TestCheckLUKS_FatalOnGarbageJSON asserts checkLUKS returns FATAL when lsblk
// returns unparseable output (DOC-02 / D-06).
func TestCheckLUKS_FatalOnGarbageJSON(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "this is not json"}})
	m := &Module{runner: r}
	findings, err := checkLUKS(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "luks" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "disk-encryption state is UNKNOWN")
}

// TestCheckLUKS_OKOnEncrypted asserts checkLUKS returns a SeverityOK finding
// when the home directory is on a LUKS-encrypted device (DOC-01 backfill).
func TestCheckLUKS_OKOnEncrypted(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: luksEncryptedJSON}})
	m := &Module{runner: r}
	findings, err := checkLUKS(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "should return an OK finding on clean encrypted path")
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "luks" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityOK, found.Severity)
}

func TestIsUnderPath(t *testing.T) {
	assert.True(t, isUnderPath("/home/alice", "/home"))
	assert.True(t, isUnderPath("/home/alice", "/home/alice"))
	assert.False(t, isUnderPath("/tmp/work", "/home"))
	assert.False(t, isUnderPath("/home2/bob", "/home"))
}

func TestIsHomeEncrypted_CryptAncestor(t *testing.T) {
	// Simulates: sda → sda1 (crypt) → dm-0 (lvm) mounted at /home
	devices := []lsblkDevice{
		{
			Name: "sda",
			Type: "disk",
			Children: []lsblkDevice{
				{
					Name: "sda1",
					Type: "crypt",
					Children: []lsblkDevice{
						{
							Name:       "dm-0",
							Type:       "lvm",
							MountPoint: "/home",
						},
					},
				},
			},
		},
	}
	assert.True(t, isHomeEncrypted("/home/alice", devices), "crypt ancestor → encrypted")
}

func TestIsHomeEncrypted_NoCrypt(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name: "sda",
			Type: "disk",
			Children: []lsblkDevice{
				{
					Name:       "sda1",
					Type:       "part",
					MountPoint: "/home",
				},
			},
		},
	}
	assert.False(t, isHomeEncrypted("/home/alice", devices), "plain partition → not encrypted")
}

func TestIsHomeEncrypted_HomeNotMounted(t *testing.T) {
	// Root is encrypted but home isn't a separate mount (/ contains /home).
	devices := []lsblkDevice{
		{
			Name: "sda1",
			Type: "crypt",
			Children: []lsblkDevice{
				{
					Name:       "dm-0",
					Type:       "lvm",
					MountPoint: "/",
				},
			},
		},
	}
	// /home/alice is under / which is on an encrypted device.
	assert.True(t, isHomeEncrypted("/home/alice", devices))
}

// TestIsHomeEncrypted_PlaintextHomeOnEncryptedRoot is the W5 regression test:
// a LUKS root (/) plus a separate PLAINTEXT /home partition must FAIL the
// encryption check — /home is where the user's data actually lives, and the
// old any-covering-mount-is-crypt logic passed because "/" also covers $HOME.
func TestIsHomeEncrypted_PlaintextHomeOnEncryptedRoot(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name: "sda",
			Type: "disk",
			Children: []lsblkDevice{
				{
					Name: "sda1",
					Type: "crypt",
					Children: []lsblkDevice{
						{Name: "dm-0", Type: "lvm", MountPoint: "/"},
					},
				},
				{
					Name:       "sda2",
					Type:       "part",
					MountPoint: "/home", // plaintext — no crypt ancestor
				},
			},
		},
	}
	assert.False(t, isHomeEncrypted("/home/alice", devices),
		"plaintext /home must fail even when / is LUKS (W5 — longest mountpoint wins)")
}

// TestIsHomeEncrypted_EncryptedHomeOnPlaintextRoot is the inverse: plaintext
// root, encrypted separate /home → pass. Also proves device ORDER does not
// matter (the / mount is seen after /home here).
func TestIsHomeEncrypted_EncryptedHomeOnPlaintextRoot(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name: "sda",
			Type: "disk",
			Children: []lsblkDevice{
				{
					Name: "sda2",
					Type: "crypt",
					Children: []lsblkDevice{
						{Name: "dm-1", Type: "lvm", MountPoint: "/home"},
					},
				},
				{Name: "sda1", Type: "part", MountPoint: "/"},
			},
		},
	}
	assert.True(t, isHomeEncrypted("/home/alice", devices),
		"encrypted /home must pass regardless of the plaintext root")
}

// TestIsHomeEncrypted_DeepestMountWins covers nested covering mounts:
// encrypted /, plaintext /home, encrypted /home/alice — the deepest mount
// hosting $HOME decides.
func TestIsHomeEncrypted_DeepestMountWins(t *testing.T) {
	devices := []lsblkDevice{
		{Name: "sda1", Type: "crypt", Children: []lsblkDevice{{Name: "dm-0", MountPoint: "/"}}},
		{Name: "sda2", Type: "part", MountPoint: "/home"},
		{Name: "sda3", Type: "crypt", Children: []lsblkDevice{{Name: "dm-1", MountPoint: "/home/alice"}}},
	}
	assert.True(t, isHomeEncrypted("/home/alice", devices),
		"the deepest covering mount (/home/alice, crypt) must win")
	assert.False(t, isHomeEncrypted("/home/bob", devices),
		"/home/bob lives on the plaintext /home partition")
}

// TestCheckLUKS_FatalOnPlaintextHomePartition runs the W5 scenario through the
// full checkLUKS path with realistic lsblk JSON.
func TestCheckLUKS_FatalOnPlaintextHomePartition(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	// Build a fixture in which "/" is crypt-backed and home's own partition is not.
	jsonOut := fmt.Sprintf(`{"blockdevices":[{"name":"sda","type":"disk","children":[`+
		`{"name":"sda1","type":"crypt","children":[{"name":"dm-0","type":"lvm","mountpoint":"/"}]},`+
		`{"name":"sda2","type":"part","mountpoint":%q}]}]}`, home)

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: jsonOut}})
	m := &Module{runner: r}
	findings, err := checkLUKS(context.Background(), m)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, modules.SeverityFatal, findings[0].Severity,
		"plaintext home partition under an encrypted root must be FATAL (W5)")
}
