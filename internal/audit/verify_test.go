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
	"github.com/abysslink/abysslink/internal/secrets"
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
	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
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
	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
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
	// R2-C2: a genuine legacy log means no HMAC key was ever created — use an
	// EMPTY store. (A keychain that DOES hold the key plus an all-legacy log
	// with no anchor is now the log-replacement attack and must FAIL — see
	// TestVerify_AnchorDeletionWithKeyFails.)
	kc := secrets.NewMockStore()
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

// TestVerify_TailStripDowngradeRejected reproduces CR-01 (iteration 2): an
// attacker who blanks prev_hash+sig on the LAST (signed) entry and rewrites its
// op/target/dry_run/hash must be caught. The legacy skip only applies to a
// contiguous unsigned HEAD prefix; a stripped tail after a started chain is
// CHAIN BROKEN tampering, not a genuine legacy entry.
func TestVerify_TailStripDowngradeRejected(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)

	// Sanity: the intact signed chain verifies.
	res0, verr0 := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr0)
	require.True(t, res0.OK)

	// Attacker: strip prev_hash+sig from the tail entry and rewrite its metadata.
	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	last := len(lines) - 1
	var e audit.Entry
	require.NoError(t, json.Unmarshal(lines[last], &e))
	e.PrevHash = "" // downgrade to "legacy"
	e.Sig = ""
	e.Target = "/etc/evil" // rewrite the audited target
	e.Op = "delete"        // rewrite the op
	e.DryRun = false       // make a planned action look real
	e.Hash = hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
	bad, _ := json.Marshal(e)
	lines[last] = bad
	require.NoError(t, os.WriteFile(logPath, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK, "stripped tail after chain start must be rejected as tampering")
	assert.Equal(t, last, res.At)
	assert.Equal(t, "CHAIN BROKEN: prev_hash stripped after chain start (tamper)", res.Reason)
}

// TestVerify_PureLegacyLogStillVerifies asserts a wholly-unsigned v1/v2 log (an
// all-empty-prev_hash prefix with no signed entries) still verifies gracefully,
// preserving backward compatibility after the CR-01 contiguous-prefix fix.
func TestVerify_PureLegacyLogStillVerifies(t *testing.T) {
	dir := t.TempDir()
	// Genuine pre-chain legacy state: no HMAC key in the keychain (R2-C2).
	kc := secrets.NewMockStore()
	logPath := filepath.Join(dir, "audit.log")

	legacy := audit.New(logPath)
	require.NoError(t, legacy.Append("write", "/etc/a", []byte("a"), false))
	require.NoError(t, legacy.Append("write", "/etc/b", []byte("b"), false))
	require.NoError(t, legacy.Append("write", "/etc/c", []byte("c"), false))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "pure legacy log must verify gracefully")
	assert.Equal(t, -1, res.At)
	assert.Equal(t, 0, res.SigsVerified)
}

// TestVerify_MixedLegacyHeadThenSignedVerifies asserts a log that begins with a
// contiguous legacy prefix and then transitions to signed entries verifies — the
// legacy skip applies to the head prefix only, and the signed tail is checked.
func TestVerify_MixedLegacyHeadThenSignedVerifies(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")

	// Two genuine legacy (unsigned) head entries.
	legacy := audit.New(logPath)
	require.NoError(t, legacy.Append("write", "/etc/a", []byte("a"), false))
	require.NoError(t, legacy.Append("write", "/etc/b", []byte("b"), false))

	// Then the chain begins (SignedAudit links its first entry to the last raw
	// line, so the chain is continuous over the legacy head).
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "legacy-head-then-signed log must verify")
	assert.Equal(t, -1, res.At)
	assert.Greater(t, res.SigsVerified, 0, "signed tail must be HMAC-verified")
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
	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	require.NoError(t, os.WriteFile(logPath, append(lines[0], '\n'), 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.TruncationDetected, "anchor.EntryCount > len(entries) must flag truncation")
}

// TestVerify_NilKeychainNoPanic reproduces CR-02: Verify(ctx, path, nil) must
// walk the chain without dereferencing a nil keychain, reporting skipped sigs.
func TestVerify_NilKeychainNoPanic(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	res, verr := audit.Verify(context.Background(), logPath, nil)
	require.NoError(t, verr, "nil keychain must not error")
	assert.True(t, res.OK, "chain structure is valid even without HMAC checks")
	assert.Equal(t, 0, res.SigsVerified, "no signatures can be verified without a key")
	assert.Greater(t, res.SigsSkipped, 0, "skipped signatures must be reported")
}

// TestVerify_ForgedAnchorRejected reproduces CR-01: a forged/unsigned anchor
// (valid JSON, invalid HMAC) must be treated as tampering, not trusted.
func TestVerify_ForgedAnchorRejected(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	// Forge the anchor: shrink EntryCount to hide a (future) truncation and
	// leave the now-stale HMAC in place. An attacker cannot produce a valid HMAC.
	anchorFile := filepath.Join(dir, "audit.anchor.json")
	data, _ := os.ReadFile(anchorFile) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	var a audit.Anchor
	require.NoError(t, json.Unmarshal(data, &a))
	a.EntryCount = 1
	bad, _ := json.Marshal(a)
	require.NoError(t, os.WriteFile(anchorFile, bad, 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK, "forged anchor HMAC must fail verification")
	assert.Equal(t, "anchor HMAC invalid (forged or tampered)", res.Reason)
}

// TestVerify_TailDryRunFlipDetected reproduces CR-03: flipping DryRun on the
// tail entry (which has no successor and so is not protected by the chain) must
// now be caught because DryRun is part of the signed input.
func TestVerify_TailDryRunFlipDetected(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	// Append a dry-run tail entry, then flip it to a real mutation.
	require.NoError(t, sa.Append(context.Background(), audit.SignInput{
		Title: "write", DiffHash: sha256.Sum256([]byte("planned")),
	}, "/etc/important", true))

	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	line := bytes.TrimRight(data, "\n")
	var e audit.Entry
	require.NoError(t, json.Unmarshal(line, &e))
	e.DryRun = false // attacker: make a planned-only action look real
	bad, _ := json.Marshal(e)
	require.NoError(t, os.WriteFile(logPath, append(bad, '\n'), 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK, "flipping tail DryRun must break the HMAC")
	assert.Equal(t, "sig mismatch", res.Reason)
}

// TestVerify_TailTargetRewriteDetected reproduces CR-03 for the Target field.
func TestVerify_TailTargetRewriteDetected(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	require.NoError(t, sa.Append(context.Background(), audit.SignInput{
		Title: "write", DiffHash: sha256.Sum256([]byte("c")),
	}, "/etc/a", false))

	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	line := bytes.TrimRight(data, "\n")
	var e audit.Entry
	require.NoError(t, json.Unmarshal(line, &e))
	e.Target = "/etc/evil" // redirect the recorded target
	bad, _ := json.Marshal(e)
	require.NoError(t, os.WriteFile(logPath, append(bad, '\n'), 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK, "rewriting tail Target must break the HMAC")
	assert.Equal(t, "sig mismatch", res.Reason)
}

// TestVerify_AnchorLastHashConsistent covers WR-01's happy path: a freshly
// written anchor's LastHash matches the log tail, so an intact log+anchor
// verifies cleanly. The mismatch (history-rewrite) branch is exercised by
// TestVerify_ForgedAnchorRejected, since rewriting the anchor's LastHash
// invalidates its HMAC (the attacker has no key).
func TestVerify_AnchorLastHashConsistent(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "intact anchor LastHash must verify")
	assert.False(t, res.TruncationDetected)
}

// TestVerify_DegradedCounter_Unknown tests AUD-02 scenario A10: when a transient
// IncrementCounter failure during Append causes the counter key to be deleted
// (the fix in signed.go), the next Verify must report CounterStatus="unknown"
// and TruncationDetected=false — NOT the permanent false alarm "mismatch".
//
// This test drives the degrade behaviour via the public surface: perform a
// normal Append with a working keychain (counter=1), then Delete the counter
// key to model exactly what Append now does on IncrementCounter failure.
// This is valid because the Delete IS the fix — it is what production code now
// executes on counter-increment failure.
func TestVerify_DegradedCounter_Unknown(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	ctx := context.Background()
	// Append one entry — counter is now 1 in the keychain.
	writeSomeEntries(t, sa, 1)

	// Simulate the degrade-to-unknown path: delete the counter key, exactly
	// as Append now does when IncrementCounter fails (AUD-02 fix).
	require.NoError(t, kc.Delete(ctx, "abysslink", "audit-counter"))

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	// A cleared counter must yield "unknown", never "mismatch".
	assert.Equal(t, "unknown", res.CounterStatus,
		"cleared counter (degrade-to-unknown) must report CounterStatus=unknown")
	assert.False(t, res.TruncationDetected,
		"cleared counter must not set TruncationDetected (no genuine truncation)")
	// Chain itself is still intact.
	assert.True(t, res.OK, "chain must be intact; only the counter check is unknown")
}

// TestVerify_GenuineTruncation_Mismatch tests AUD-02 scenario T-24-06-02: a
// genuine tail truncation (counter present and disagrees with entry count) must
// still produce CounterStatus="mismatch" and TruncationDetected=true.
//
// We set up a clean log with N entries (counter=N), then overwrite the counter
// to N+1 to simulate the attacker/truncation scenario where the log is shorter
// than the counter records.
func TestVerify_GenuineTruncation_Mismatch(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	ctx := context.Background()
	const entryCount = 4
	writeSomeEntries(t, sa, entryCount)

	// Write a counter that is larger than the actual entry count, simulating
	// tail truncation (log has 4 entries but counter says 5 were appended).
	require.NoError(t, audit.WriteCounter(ctx, kc, entryCount+1))

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.Equal(t, "mismatch", res.CounterStatus,
		"genuine truncation (counter > entries) must report CounterStatus=mismatch")
	assert.True(t, res.TruncationDetected,
		"genuine truncation must set TruncationDetected=true")
}

// TestVerify_NoCounter_Unknown is a regression guard for pre-AUD-02 logs: a log
// written without any counter (counter key was never set in the keychain) must
// produce CounterStatus="unknown" — the honest tri-state result for "counter
// was never recorded", not a spurious "mismatch" alarm.
func TestVerify_NoCounter_Unknown(t *testing.T) {
	dir := t.TempDir()
	// Genuine pre-AUD-02 legacy state: no HMAC key, no counter (R2-C2).
	kc := secrets.NewMockStore()
	logPath := filepath.Join(dir, "audit.log")

	ctx := context.Background()
	// Write a log using the plain (unsigned) Audit — no counter is ever written.
	legacy := audit.New(logPath)
	require.NoError(t, legacy.Append("write", "/etc/a", []byte("a"), false))
	require.NoError(t, legacy.Append("write", "/etc/b", []byte("b"), false))

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.Equal(t, "unknown", res.CounterStatus,
		"pre-AUD-02 log with no counter must report CounterStatus=unknown (regression guard)")
	assert.False(t, res.TruncationDetected,
		"missing counter must not set TruncationDetected")
}
