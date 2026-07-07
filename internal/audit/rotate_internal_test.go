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

package audit

// ROT-03: multi-epoch chain verification regression tests, including the
// attack battery derived from the journald FSS analysis (CVE-2023-31437/38/39
// — reseal-with-newer-key, epoch-boundary truncation, epoch skips) and the
// TUF custody-handoff properties (marker fingerprint binding). These are
// INTERNAL tests: crafting attack entries requires the epoch framing helpers.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/secrets"
)

// rotTestRig builds a signed chain with nEntriesPerEpoch entries per epoch and
// (epochs-1) rotations, returning the SignedAudit, its log path, and the store.
func rotTestRig(t *testing.T, epochs, nEntriesPerEpoch int) (*SignedAudit, string, *secrets.MockStore) {
	t.Helper()
	kc := secrets.NewMockStore()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	sa, err := NewSigned(logPath, kc)
	require.NoError(t, err)
	ctx := context.Background()
	for e := 1; e <= epochs; e++ {
		for i := 0; i < nEntriesPerEpoch; i++ {
			content := []byte(fmt.Sprintf("epoch-%d-entry-%d", e, i))
			sum := sha256.Sum256(content)
			require.NoError(t, sa.Append(ctx, SignInput{Title: "write", DiffHash: sum},
				fmt.Sprintf("/tmp/target-%d-%d", e, i), false))
		}
		if e < epochs {
			res, rerr := sa.RotateHMACKey(ctx)
			require.NoError(t, rerr)
			require.True(t, res.Completed)
			require.Equal(t, uint32(e), res.OldEpoch)   //nolint:gosec // test values are tiny
			require.Equal(t, uint32(e+1), res.NewEpoch) //nolint:gosec // test values are tiny
			require.Len(t, res.NewKeyFingerprint, sha256.Size*2)
		}
	}
	return sa, logPath, kc
}

func mustVerify(t *testing.T, logPath string, kc KeychainStore) VerifyResult {
	t.Helper()
	res, err := Verify(context.Background(), logPath, kc)
	require.NoError(t, err)
	return res
}

func readLines(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned path
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	return lines
}

func writeLines(t *testing.T, logPath string, lines []string) {
	t.Helper()
	require.NoError(t, os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
}

// rechainFrom recomputes prev_hash links (and nothing else) from index start
// so structural chain checks pass and the ATTACK under test is what fails.
func rechainFrom(t *testing.T, lines []string, start int) []string {
	t.Helper()
	for i := start; i < len(lines); i++ {
		var e Entry
		require.NoError(t, json.Unmarshal([]byte(lines[i]), &e))
		if i == 0 {
			e.PrevHash = genesisMarker
		} else {
			sum := sha256.Sum256([]byte(lines[i-1]))
			e.PrevHash = hex.EncodeToString(sum[:])
		}
		b, err := json.Marshal(e)
		require.NoError(t, err)
		lines[i] = string(b)
	}
	return lines
}

func TestRotate_MultiEpochChainVerifies(t *testing.T) {
	_, logPath, kc := rotTestRig(t, 3, 4)
	res := mustVerify(t, logPath, kc)
	require.True(t, res.OK, "reason: %s", res.Reason)
	require.False(t, res.TruncationDetected)
	require.False(t, res.Indeterminate)
	// 3 epochs * 4 entries + 2 rotation markers, all signed and verified.
	require.Equal(t, 14, res.SigsVerified)
	require.Zero(t, res.SigsSkipped)
	require.Equal(t, "verified", res.CounterStatus)
}

func TestRotate_PreRotationHistoryStaysValid(t *testing.T) {
	// ROT-01 acceptance: verification selects the key by epoch so
	// pre-rotation history stays VALID — no false TAMPERED.
	_, logPath, kc := rotTestRig(t, 2, 3)
	res := mustVerify(t, logPath, kc)
	require.True(t, res.OK, "pre-rotation entries must stay valid, got: %s", res.Reason)
}

func TestRotate_AnchorCarriesEpochAndVerifies(t *testing.T) {
	_, logPath, kc := rotTestRig(t, 2, 2)
	anchor, err := ReadAnchor(logPath)
	require.NoError(t, err)
	require.NotNil(t, anchor)
	require.Equal(t, uint32(2), anchor.KeyEpoch)
	ok, err := VerifyAnchor(logPath, kc)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerify_ResealWithNewerKeyRejected(t *testing.T) {
	// CVE-2023-31439 scenario: an attacker holding a RETAINED key rewrites a
	// pre-rotation entry and reseals it under the epoch-2 key, declaring
	// key_epoch=2. Chain-position rule (V2) must reject it even though the
	// signature itself is cryptographically valid under the declared epoch.
	_, logPath, kc := rotTestRig(t, 2, 3)
	ctx := context.Background()
	key2, err := fetchHMACKeyEpoch(ctx, kc, 2)
	require.NoError(t, err)

	lines := readLines(t, logPath)
	// Entry 1 is a pre-rotation (epoch 1) entry. Rewrite its op and reseal.
	var e Entry
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &e))
	e.Op = "totally-legit-op"
	e.KeyEpoch = 2
	in := SignInput{Title: e.Op, Target: e.Target, Time: e.Time.UTC().Format(time.RFC3339), DryRun: e.DryRun, PrevHash: e.PrevHash}
	raw, derr := hex.DecodeString(e.Hash)
	require.NoError(t, derr)
	copy(in.DiffHash[:], raw)
	e.Sig = computeSigEpoch(key2, in, 2)
	b, merr := json.Marshal(e)
	require.NoError(t, merr)
	lines[1] = string(b)
	writeLines(t, logPath, rechainFrom(t, lines, 2))

	res := mustVerify(t, logPath, kc)
	require.False(t, res.OK)
	require.Contains(t, res.Reason, "reseal")
	require.False(t, res.Indeterminate, "a reseal is TAMPER, never indeterminate")
}

func TestVerify_StrippedEpochFieldRejected(t *testing.T) {
	// The declared epoch of a post-rotation entry is MAC-covered: stripping
	// key_epoch downgrades the entry to epoch-1 framing, which fails V2
	// (position says epoch 2) — and even if position matched, the signature
	// would no longer verify under epoch-1 framing.
	_, logPath, kc := rotTestRig(t, 2, 3)
	lines := readLines(t, logPath)
	idx := len(lines) - 1 // last entry: epoch 2
	var e Entry
	require.NoError(t, json.Unmarshal([]byte(lines[idx]), &e))
	require.Equal(t, uint32(2), e.KeyEpoch)
	e.KeyEpoch = 0 // strip
	b, err := json.Marshal(e)
	require.NoError(t, err)
	lines[idx] = string(b)
	writeLines(t, logPath, lines)

	res := mustVerify(t, logPath, kc)
	require.False(t, res.OK)
	require.Contains(t, res.Reason, "does not match chain-position")
}

func TestVerify_TruncationAtRotationBoundary(t *testing.T) {
	// CVE-2023-31438 scenario: cut the log just before the rotation marker so
	// it looks like a clean pre-rotation log. The keychain pointer (epoch 2)
	// must expose the missing tail.
	_, logPath, kc := rotTestRig(t, 2, 3)
	lines := readLines(t, logPath)
	// Keep only the 3 epoch-1 entries (drop marker + epoch-2 entries).
	writeLines(t, logPath, lines[:3])
	// Refresh the anchor to match the truncated log so ONLY the epoch check
	// can catch it (the anchor & counter would catch it independently).
	key1, err := fetchHMACKeyEpoch(context.Background(), kc, 1)
	require.NoError(t, err)
	require.NoError(t, writeAnchorWithKey(context.Background(), logPath, key1, 1))
	require.NoError(t, WriteCounter(context.Background(), kc, 3))

	res := mustVerify(t, logPath, kc)
	require.False(t, res.OK)
	require.True(t, res.TruncationDetected)
	require.Contains(t, res.Reason, "truncation at rotation boundary")
}

func TestVerify_EpochSkipRejected(t *testing.T) {
	// Continuity (V3): a forged marker jumping 1 -> 3 must be rejected even
	// when its signature is valid under the current key.
	sa, logPath, kc := rotTestRig(t, 1, 2)
	ctx := context.Background()
	// Store a key at epoch 3 and forge a marker pointing at it.
	fresh := make([]byte, hmacKeyBytes)
	for i := range fresh {
		fresh[i] = 7
	}
	require.NoError(t, kc.Set(ctx, hmacKeyService, epochAccount(3), hex.EncodeToString(fresh)))
	fp := sha256.Sum256(fresh)
	var diff [32]byte
	copy(diff[:], fp[:])
	require.NoError(t, sa.Append(ctx, SignInput{Title: opRotate, DiffHash: diff}, "epoch:3", false))

	res := mustVerify(t, logPath, kc)
	require.False(t, res.OK)
	require.Contains(t, res.Reason, "continuity")
}

func TestVerify_MarkerFingerprintMismatch(t *testing.T) {
	// Custody binding (V4): the marker must fingerprint the ACTUAL stored
	// epoch-2 key. Swap the stored key after rotation -> mismatch.
	_, logPath, kc := rotTestRig(t, 2, 2)
	ctx := context.Background()
	other := make([]byte, hmacKeyBytes)
	for i := range other {
		other[i] = 9
	}
	require.NoError(t, kc.Set(ctx, hmacKeyService, epochAccount(2), hex.EncodeToString(other)))

	res := mustVerify(t, logPath, kc)
	require.False(t, res.OK)
	// The swapped key surfaces at the marker: fingerprint mismatch (or the
	// first epoch-2 sig failing, depending on walk order — marker comes first).
	require.Contains(t, res.Reason, "fingerprint mismatch")
}

func TestVerify_MissingRotatedKeyIsIndeterminate(t *testing.T) {
	// V6: a rotated chain whose epoch-2 key vanished is UNVERIFIABLE — fail
	// closed but lexically distinct from tampering.
	_, logPath, kc := rotTestRig(t, 2, 2)
	require.NoError(t, kc.Delete(context.Background(), hmacKeyService, epochAccount(2)))

	res := mustVerify(t, logPath, kc)
	require.False(t, res.OK)
	require.True(t, res.Indeterminate)
	require.NotContains(t, strings.ToLower(res.Reason), "tamper")
}

func TestRotate_HalfStateRecovery(t *testing.T) {
	// Crash window: marker appended + new key stored, pointer NOT advanced.
	sa, logPath, kc := rotTestRig(t, 1, 2)
	ctx := context.Background()

	// Simulate the half-state manually (steps 1-2 of RotateHMACKey).
	fresh := make([]byte, hmacKeyBytes)
	for i := range fresh {
		fresh[i] = 5
	}
	require.NoError(t, kc.Set(ctx, hmacKeyService, epochAccount(2), hex.EncodeToString(fresh)))
	fp := sha256.Sum256(fresh)
	var diff [32]byte
	copy(diff[:], fp[:])
	require.NoError(t, sa.appendNoRefreshForTest(ctx, SignInput{Title: opRotate, DiffHash: diff}, "epoch:2", false))

	// (a) Regular appends fail closed with the recovery hint.
	sum := sha256.Sum256([]byte("post-crash"))
	err := sa.Append(ctx, SignInput{Title: "write", DiffHash: sum}, "/tmp/x", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rotation incomplete")

	// (b) Re-running rotation COMPLETES the half-state instead of stacking a
	// second rotation.
	res, rerr := sa.RotateHMACKey(ctx)
	require.NoError(t, rerr)
	require.True(t, res.Resumed)
	require.Equal(t, uint32(2), res.NewEpoch)

	// (c) Everything verifies afterwards, and appends work again.
	require.NoError(t, sa.Append(ctx, SignInput{Title: "write", DiffHash: sum}, "/tmp/x", false))
	v := mustVerify(t, logPath, kc)
	require.True(t, v.OK, "reason: %s", v.Reason)
}

func TestRotatePreview_IsReadOnly(t *testing.T) {
	sa, logPath, kc := rotTestRig(t, 1, 2)
	ctx := context.Background()
	linesBefore := readLines(t, logPath)

	res, err := RotatePreview(ctx, logPath, kc)
	require.NoError(t, err)
	require.False(t, res.Completed)
	require.Equal(t, uint32(1), res.OldEpoch)
	require.Equal(t, uint32(2), res.NewEpoch)

	// No mutation: no epoch-2 key, pointer unchanged, chain untouched.
	_, kerr := fetchHMACKeyEpoch(ctx, kc, 2)
	require.Error(t, kerr)
	ep, perr := readEpochPointer(ctx, kc)
	require.NoError(t, perr)
	require.Equal(t, uint32(1), ep)
	require.Equal(t, linesBefore, readLines(t, logPath))
	_ = sa
}

// appendNoRefreshForTest exposes the locked append primitive for crash-window
// simulation. Production code never uses it.
func (a *SignedAudit) appendNoRefreshForTest(ctx context.Context, in SignInput, target string, dryRun bool) error {
	a.mu.Lock()
	lockFD, err := acquireAuditLock(a.logPath)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	defer func() {
		releaseAuditLock(lockFD)
		a.mu.Unlock()
	}()
	return a.appendNoRefresh(ctx, in, target, dryRun)
}
