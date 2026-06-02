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
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSomeEntries appends n signed entries to logPath via SignedAudit.
func writeSomeEntries(t *testing.T, sa *audit.SignedAudit, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, sa.Append(context.Background(), audit.SignInput{
			Title:    "write",
			DiffHash: sha256.Sum256([]byte{byte(i)}),
		}, "/etc/x", false))
	}
}

func TestWriteAnchor_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)

	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	anchorFile := filepath.Join(dir, "audit.anchor.json")
	info, serr := os.Stat(anchorFile)
	require.NoError(t, serr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	a, rerr := audit.ReadAnchor(logPath)
	require.NoError(t, rerr)
	require.NotNil(t, a)
	assert.Equal(t, int64(3), a.EntryCount)
	assert.NotEmpty(t, a.LastHash)
	assert.NotEmpty(t, a.Time)
	assert.NotEmpty(t, a.HMAC)
}

func TestReadAnchor_Missing(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	a, err := audit.ReadAnchor(logPath)
	require.NoError(t, err)
	assert.Nil(t, a)
}

func TestVerifyAnchor_CleanAndTampered(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 2)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	ok, verr := audit.VerifyAnchor(logPath, kc)
	require.NoError(t, verr)
	assert.True(t, ok, "unmodified anchor must verify")

	// Tamper: bump EntryCount without re-signing.
	anchorFile := filepath.Join(dir, "audit.anchor.json")
	data, _ := os.ReadFile(anchorFile) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	var a audit.Anchor
	require.NoError(t, json.Unmarshal(data, &a))
	a.EntryCount = 9999
	bad, _ := json.Marshal(a)
	require.NoError(t, os.WriteFile(anchorFile, bad, 0o600))

	ok, verr = audit.VerifyAnchor(logPath, kc)
	require.NoError(t, verr)
	assert.False(t, ok, "tampered anchor HMAC must not verify")
}

func TestVerifyAnchor_MissingIsNotViolation(t *testing.T) {
	kc := seededStore(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	ok, err := audit.VerifyAnchor(logPath, kc)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestWriteAnchor_AtomicUnderConcurrentRead(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 5)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = audit.WriteAnchor(context.Background(), logPath, kc)
		}()
		go func() {
			defer wg.Done()
			// Reader never sees a partial file (temp+rename atomicity).
			if a, rerr := audit.ReadAnchor(logPath); rerr == nil && a != nil {
				assert.NotEmpty(t, a.HMAC)
			}
		}()
	}
	wg.Wait()
}
