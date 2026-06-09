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

package audit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
)

// unavailableKC simulates a keychain that exists but cannot be reached
// (locked, denied, dbus down). Get returns an error that is NOT
// secrets.ErrNotFound; Set/Delete calls are counted so tests can assert the
// fail-closed contract never writes.
type unavailableKC struct {
	getErr   error
	setCalls int
	delCalls int
}

func (u *unavailableKC) Set(_ context.Context, _, _, _ string) error {
	u.setCalls++
	return nil
}

func (u *unavailableKC) Get(_ context.Context, _, _ string) (string, error) {
	return "", u.getErr
}

func (u *unavailableKC) Delete(_ context.Context, _, _ string) error {
	u.delCalls++
	return nil
}

// TestNewSigned_FailsClosedOnUnavailableKeychain proves CORE-04: a transient
// keychain failure (anything other than ErrNotFound) must propagate as an
// error WITHOUT generating and storing a fresh HMAC key — overwriting the
// existing key would permanently break verification of the whole chain.
func TestNewSigned_FailsClosedOnUnavailableKeychain(t *testing.T) {
	kc := &unavailableKC{getErr: errors.New("keychain unavailable: dbus down")}
	logPath := filepath.Join(t.TempDir(), "audit.log")

	sa, err := audit.NewSigned(logPath, kc)
	require.Error(t, err)
	assert.Nil(t, sa)
	assert.Contains(t, err.Error(), "keychain unavailable")
	assert.Zero(t, kc.setCalls, "fail-closed: NewSigned must NOT overwrite the HMAC key on a transient keychain error")
}

// TestNewSigned_GeneratesOnlyOnNotFound proves the CORE-04 counterpart: a
// definitive "key absent" (ErrNotFound) still auto-generates and stores a key.
func TestNewSigned_GeneratesOnlyOnNotFound(t *testing.T) {
	kc := secrets.NewMockStore() // Get on empty store wraps ErrNotFound
	logPath := filepath.Join(t.TempDir(), "audit.log")

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	require.NotNil(t, sa)

	// The generated key must now be retrievable.
	_, gerr := kc.Get(context.Background(), "abysslink", "audit-hmac")
	assert.NoError(t, gerr, "HMAC key must have been generated and stored")
}

// TestWriteFile_RefusesSymlinkTarget proves CORE-03: the unsigned WriteFile
// must not write "through" a symlink — doing so would back up and replace a
// file outside the audited path.
func TestWriteFile_RefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.conf")
	require.NoError(t, os.WriteFile(victim, []byte("untouchable"), 0o600))

	link := filepath.Join(dir, "link.conf")
	require.NoError(t, os.Symlink(victim, link))

	a := audit.New(filepath.Join(dir, "audit.log"))
	err := a.WriteFile(link, []byte("attack"), 0o600, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")

	// The symlink target must be untouched.
	got, rerr := os.ReadFile(victim) //nolint:gosec // G304: test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "untouchable", string(got))
}

// TestWriteFile_AppendsBeforeWrite proves CORE-07 observable ordering: after a
// successful unsigned WriteFile the audit entry exists; and when the physical
// write cannot complete (unwritable directory), the intent entry is still
// recorded — never an unrecorded mutation.
func TestWriteFile_AppendsBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	roDir := filepath.Join(dir, "ro")
	require.NoError(t, os.Mkdir(roDir, 0o500)) // no write permission → CreateTemp fails
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })

	target := filepath.Join(roDir, "blocked.conf")
	a := audit.New(logPath)
	err := a.WriteFile(target, []byte("content"), 0o600, false)
	require.Error(t, err, "write into read-only dir must fail")

	// CORE-07: the intent was recorded BEFORE the failed physical write.
	entries, rerr := audit.ReadLog(logPath)
	require.NoError(t, rerr)
	require.Len(t, entries, 1)
	assert.Equal(t, "write", entries[0].Op)
	assert.Equal(t, target, entries[0].Target)
}

// TestReverse_ChainAttestedBackupBeatsPlantedBak proves CORE-06: when a signed
// chain entry attests a backup, Reverse restores THAT backup — an
// attacker-planted, lexically-first .bak must not win glob ordering.
func TestReverse_ChainAttestedBackupBeatsPlantedBak(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "cfg.conf")
	kc := secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(target, []byte("ORIGINAL"), 0o600))
	require.NoError(t, sa.WriteFile(target, []byte("MODIFIED"), 0o600, false))

	// Attacker plants a lexically-FIRST .bak (sorts before any real stamp).
	planted := target + ".bak.00000000T000000.000000000Z"
	require.NoError(t, os.WriteFile(planted, []byte("EVIL"), 0o600))

	plan, err := audit.PlanReverse(logPath)
	require.NoError(t, err)
	require.Len(t, plan, 1)
	assert.Equal(t, "restore", plan[0].Action)
	assert.NotEqual(t, planted, plan[0].Backup, "planted .bak must not be selected")
	assert.NotEmpty(t, plan[0].ChainHash, "chain-attested restore must carry the expected hash")
	assert.Empty(t, plan[0].Warning)

	manifest, err := audit.Reverse(logPath, false)
	require.NoError(t, err)
	require.Len(t, manifest, 1)
	require.NoError(t, manifest[0].Err)

	got, rerr := os.ReadFile(target) //nolint:gosec // G304: test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "ORIGINAL", string(got), "must restore the chain-attested content, not the planted one")
}

// TestReverse_RefusesTamperedChainBackup proves CORE-06: if the
// chain-attested .bak content no longer matches the signed chain entry's
// hash, the restore is refused and the target is left untouched.
func TestReverse_RefusesTamperedChainBackup(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "cfg.conf")
	kc := secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(target, []byte("ORIGINAL"), 0o600))
	require.NoError(t, sa.WriteFile(target, []byte("MODIFIED"), 0o600, false))

	// Tamper with the chain-attested backup.
	baks, err := audit.BackupsFromChain(logPath, target)
	require.NoError(t, err)
	require.Len(t, baks, 1)
	require.NoError(t, os.WriteFile(baks[0].Target, []byte("EVIL"), 0o600))

	manifest, err := audit.Reverse(logPath, false)
	require.NoError(t, err)
	require.Len(t, manifest, 1)
	require.Error(t, manifest[0].Err, "tampered backup must be refused")
	assert.Contains(t, manifest[0].Err.Error(), "does not match signed chain entry hash")

	// Target untouched by the refused restore.
	got, rerr := os.ReadFile(target) //nolint:gosec // G304: test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "MODIFIED", string(got))
}

// TestPlanReverse_GlobFallbackCarriesWarning proves CORE-06: with a legacy
// unsigned log (no chain backup entries), glob selection still works but the
// plan says so explicitly via Warning and an empty ChainHash.
func TestPlanReverse_GlobFallbackCarriesWarning(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "old.conf")
	a := audit.New(logPath)

	require.NoError(t, os.WriteFile(target, []byte("ORIGINAL"), 0o600))
	require.NoError(t, a.WriteFile(target, []byte("MODIFIED"), 0o600, false))

	plan, err := audit.PlanReverse(logPath)
	require.NoError(t, err)
	require.Len(t, plan, 1)
	assert.Equal(t, "restore", plan[0].Action)
	assert.Empty(t, plan[0].ChainHash)
	assert.NotEmpty(t, plan[0].Warning, "glob fallback must be flagged as unverified")
}
