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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify_CleanChain(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 5)

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK)
	assert.Equal(t, -1, res.At)
	assert.False(t, res.TruncationDetected)
}

func TestVerify_CorruptedPrevHashAtIndex2(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 4)

	// Corrupt entry[2].PrevHash by rewriting the line in place.
	data, _ := os.ReadFile(logPath) //nolint:gosec
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	require.GreaterOrEqual(t, len(lines), 3)
	var e audit.Entry
	require.NoError(t, json.Unmarshal(lines[2], &e))
	e.PrevHash = hex.EncodeToString(sha256.New().Sum(nil)) // wrong but well-formed
	bad, _ := json.Marshal(e)
	lines[2] = bad
	require.NoError(t, os.WriteFile(logPath, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK)
	assert.Equal(t, 2, res.At)
	assert.Equal(t, "prev_hash mismatch", res.Reason)
}

func TestVerify_SigMismatch(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 1)

	// Corrupt the sig of the only (genesis) entry; prev_hash stays valid.
	data, _ := os.ReadFile(logPath) //nolint:gosec
	line := bytes.TrimRight(data, "\n")
	var e audit.Entry
	require.NoError(t, json.Unmarshal(line, &e))
	e.Sig = hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	bad, _ := json.Marshal(e)
	require.NoError(t, os.WriteFile(logPath, append(bad, '\n'), 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK)
	assert.Equal(t, 0, res.At)
	assert.Equal(t, "sig mismatch", res.Reason)
}

func TestVerify_LegacyEntriesSkipped(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")

	// Write two legacy unsigned entries (no prev_hash/sig) via the plain Audit.
	legacy := audit.New(logPath)
	require.NoError(t, legacy.Append("write", "/etc/a", []byte("a"), false))
	require.NoError(t, legacy.Append("write", "/etc/b", []byte("b"), false))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "legacy unsigned entries must be skipped, not fail")
	assert.Equal(t, -1, res.At)
}

func TestVerify_TruncationDetected(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	// Truncate the log to a single entry, keeping the chain valid for entry 0.
	data, _ := os.ReadFile(logPath) //nolint:gosec
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	require.NoError(t, os.WriteFile(logPath, append(lines[0], '\n'), 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.TruncationDetected, "anchor.EntryCount > len(entries) must flag truncation")
}
