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
	"testing"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiskEncryptionStatus_On_IsEncrypted: a clean "FileVault is On." maps to
// DiskEncrypted.
func TestDiskEncryptionStatus_On_IsEncrypted(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "FileVault is On.\n"}})
	p := New(r)
	state, err := p.DiskEncryptionStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, platform.DiskEncrypted, state)
}

// TestDiskEncryptionStatus_Off_IsUnencrypted: "FileVault is Off." maps to
// DiskUnencrypted.
func TestDiskEncryptionStatus_Off_IsUnencrypted(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "FileVault is Off.\n"}})
	p := New(r)
	state, err := p.DiskEncryptionStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, platform.DiskUnencrypted, state)
}

// TestDiskEncryptionStatus_InProgress_IsEncrypting is the core BKLG-02 fix: real
// macOS prints "FileVault is On. Encryption in progress …" mid-encryption, which
// STARTS WITH "FileVault is On" — it must map to DiskEncrypting (not-safe), never
// DiskEncrypted. Deferred and decryption states map the same way.
func TestDiskEncryptionStatus_InProgress_IsEncrypting(t *testing.T) {
	cases := map[string]string{
		"encryption-in-progress": "FileVault is On.\nEncryption in progress: Percent completed = 42.0",
		"deferred-enablement":    "FileVault is On.\nDeferred enablement appears to be active for user.",
		"decryption-in-progress": "FileVault is On.\nDecryption in progress: Percent completed = 7.0",
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: out}})
			p := New(r)
			state, err := p.DiskEncryptionStatus(context.Background())
			require.NoError(t, err)
			assert.Equal(t, platform.DiskEncrypting, state,
				"mid-encryption/decryption/deferred must be DiskEncrypting, never DiskEncrypted")
			assert.NotEqual(t, platform.DiskEncrypted, state)
		})
	}
}

// TestDiskEncryptionStatus_NonZeroExit_IsUnknown: a non-zero fdesetup exit fails
// closed to DiskUnknown (never "unencrypted"/"encrypted").
func TestDiskEncryptionStatus_NonZeroExit_IsUnknown(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{
		Stdout: "FileVault is On.", ExitCode: 1, Stderr: "boom",
	}})
	p := New(r)
	state, err := p.DiskEncryptionStatus(context.Background())
	require.Error(t, err)
	assert.Equal(t, platform.DiskUnknown, state)
}

// TestDiskEncryptionStatus_GarbageOutput_FailsClosed: unrecognized output maps to
// DiskUnknown, NEVER DiskEncrypted.
func TestDiskEncryptionStatus_GarbageOutput_FailsClosed(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "wat"}})
	p := New(r)
	state, err := p.DiskEncryptionStatus(context.Background())
	require.Error(t, err)
	assert.Equal(t, platform.DiskUnknown, state)
	assert.NotEqual(t, platform.DiskEncrypted, state, "garbage output must never report encrypted")
}
