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

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/abysslink/abysslink/internal/secrets"
)

// RotateResult reports a completed (or previewed) HMAC key rotation (ROT-02).
// It never carries key material — fingerprints only.
type RotateResult struct {
	OldEpoch          uint32 `json:"old_epoch"`
	NewEpoch          uint32 `json:"new_epoch"`
	NewKeyFingerprint string `json:"new_key_fingerprint"` // hex sha256 of the new key
	Completed         bool   `json:"completed"`           // false for dry-run previews
	Resumed           bool   `json:"resumed"`             // true when a half-finished rotation was completed
}

// RotatePreview reports what a rotation WOULD do (the --dry-run default).
// Read-only: no key generation, no keychain writes, no chain append.
func RotatePreview(ctx context.Context, logPath string, kc KeychainStore) (RotateResult, error) {
	epoch, err := readEpochPointer(ctx, kc)
	if err != nil {
		return RotateResult{}, err
	}
	tail, terr := tailEpoch(logPath)
	if terr != nil {
		return RotateResult{}, terr
	}
	if tail > epoch {
		// Half-finished rotation: --apply would complete it, not start another.
		return RotateResult{OldEpoch: epoch, NewEpoch: tail, Resumed: true}, nil
	}
	return RotateResult{OldEpoch: epoch, NewEpoch: epoch + 1}, nil
}

// RotateHMACKey rotates the audit-chain HMAC key to a fresh epoch (ROT-02):
//
//  1. generate the new 32-byte key and store it at audit-hmac-e<new> FIRST —
//     an orphaned key from a crash here is harmless and simply overwritten by
//     a re-run, because no marker references it yet;
//  2. append the in-chain rotation marker, signed by the OLD key under the OLD
//     epoch's framing (TUF-style custody handoff): Target="epoch:<new>",
//     Hash=sha256(new key) binds the successor without exposing key material;
//  3. advance the keychain epoch pointer;
//  4. re-anchor under the NEW key.
//
// Crash between 2 and 3 leaves the chain one epoch ahead of the pointer:
// regular appends fail closed with a recovery hint (appendNoRefresh's
// tailEpoch guard), doctor's sec-audit-epoch check flags it, and a re-run of
// this function COMPLETES the rotation (steps 3–4) instead of starting a new
// one — the marker's fingerprint is checked against the stored key so a
// mismatched half-state is never silently adopted.
//
// The old key is RETAINED in the keychain forever: verification of
// pre-rotation history depends on it (never deleted, ROT-02). Everything runs
// under the audit mutex + cross-process flock — the same critical section
// every append uses — so no entry can interleave between the marker and the
// pointer advance, and two concurrent rotations serialise.
func (a *SignedAudit) RotateHMACKey(ctx context.Context) (RotateResult, error) {
	a.mu.Lock()
	lockFD, lerr := acquireAuditLock(a.logPath)
	if lerr != nil {
		a.mu.Unlock()
		return RotateResult{}, fmt.Errorf("audit: acquire process lock: %w", lerr)
	}
	unlocked := false
	unlock := func() {
		if unlocked {
			return
		}
		unlocked = true
		releaseAuditLock(lockFD)
		a.mu.Unlock()
	}
	defer unlock()

	// Current epoch + key, fail closed on any keychain unavailability. A chain
	// that never generated a key has nothing to rotate.
	oldEpoch, err := readEpochPointer(ctx, a.kc)
	if err != nil {
		return RotateResult{}, err
	}
	if _, kerr := fetchHMACKeyEpoch(ctx, a.kc, oldEpoch); kerr != nil {
		if errors.Is(kerr, secrets.ErrNotFound) {
			return RotateResult{}, fmt.Errorf("audit: no HMAC key exists yet (epoch %d) — nothing to rotate; the key is created on the first signed append", oldEpoch)
		}
		return RotateResult{}, kerr
	}

	// Resume path: marker already in the chain, pointer not yet advanced.
	tail, terr := tailEpoch(a.logPath)
	if terr != nil {
		return RotateResult{}, terr
	}
	if tail > oldEpoch {
		return a.completeRotationLocked(ctx, oldEpoch, tail)
	}

	newEpoch := oldEpoch + 1

	// (1) Generate + store the new key BEFORE the marker references it.
	fresh := make([]byte, hmacKeyBytes)
	if _, rerr := io.ReadFull(rand.Reader, fresh); rerr != nil {
		return RotateResult{}, fmt.Errorf("audit: generate hmac key (epoch %d): %w", newEpoch, rerr)
	}
	if serr := a.kc.Set(ctx, hmacKeyService, epochAccount(newEpoch), hex.EncodeToString(fresh)); serr != nil {
		return RotateResult{}, fmt.Errorf("audit: store hmac key (epoch %d): %w", newEpoch, serr)
	}
	fp := sha256.Sum256(fresh)

	// (2) In-chain marker, signed by the OLD key (the cached key/epoch pair is
	// exactly the old epoch's — appendNoRefresh stamps and signs with it).
	var diff [32]byte
	copy(diff[:], fp[:])
	if aerr := a.appendNoRefresh(ctx, SignInput{Title: opRotate, DiffHash: diff}, fmt.Sprintf("epoch:%d", newEpoch), false); aerr != nil {
		return RotateResult{}, fmt.Errorf("audit: append rotation marker: %w", aerr)
	}

	// (3) Advance the pointer; from here every writer signs under the new key.
	if perr := writeEpochPointer(ctx, a.kc, newEpoch); perr != nil {
		return RotateResult{}, fmt.Errorf("audit: rotation marker recorded but pointer advance failed — appends now fail closed; re-run `abysslink rotate audit-hmac --apply` to complete: %w", perr)
	}

	// Refresh the in-memory cache to the new epoch.
	a.keyMu.Lock()
	a.setKeyLocked(fresh, newEpoch)
	a.keyMu.Unlock()

	// (4) Re-anchor under the new key (ROT-02). Counter semantics unchanged:
	// the marker is one entry.
	if aerr := writeAnchorWithKey(ctx, a.logPath, fresh, newEpoch); aerr != nil {
		return RotateResult{}, fmt.Errorf("audit: post-rotation anchor write failed: %w", aerr)
	}
	if cerr := IncrementCounter(ctx, a.kc); cerr != nil {
		// Same fail-soft contract as every append: a lagging counter degrades
		// to CounterStatus="unknown", never a false tamper alarm (R2-I2).
		slog.Warn("audit: keychain counter increment failed after rotation; counter now lags the log (Verify reports unknown)",
			"err", cerr, "log", a.logPath)
	}

	return RotateResult{
		OldEpoch:          oldEpoch,
		NewEpoch:          newEpoch,
		NewKeyFingerprint: hex.EncodeToString(fp[:]),
		Completed:         true,
	}, nil
}

// completeRotationLocked finishes a half-done rotation (marker in chain,
// pointer lagging): it validates the marker's fingerprint against the stored
// new-epoch key, then advances the pointer and re-anchors. MUST be called with
// a.mu and the flock held.
func (a *SignedAudit) completeRotationLocked(ctx context.Context, oldEpoch, newEpoch uint32) (RotateResult, error) {
	if newEpoch != oldEpoch+1 {
		return RotateResult{}, fmt.Errorf("audit: chain tail epoch %d is not pointer epoch %d + 1 — chain/keychain state needs manual inspection", newEpoch, oldEpoch)
	}
	newKey, kerr := fetchHMACKeyEpoch(ctx, a.kc, newEpoch)
	if kerr != nil {
		return RotateResult{}, fmt.Errorf("audit: half-finished rotation but epoch %d key unavailable: %w", newEpoch, kerr)
	}
	// The marker's fingerprint must match the stored key before we adopt it.
	last, lerr := readLastNonEmptyLine(a.logPath)
	if lerr != nil {
		return RotateResult{}, lerr
	}
	var marker Entry
	if uerr := json.Unmarshal(last, &marker); uerr != nil {
		return RotateResult{}, fmt.Errorf("audit: parse rotation marker: %w", uerr)
	}
	fp := sha256.Sum256(newKey)
	if marker.Hash != hex.EncodeToString(fp[:]) {
		return RotateResult{}, fmt.Errorf("audit: rotation marker fingerprint does not match the stored epoch %d key — refusing to complete (fail closed)", newEpoch)
	}
	if perr := writeEpochPointer(ctx, a.kc, newEpoch); perr != nil {
		return RotateResult{}, fmt.Errorf("audit: pointer advance failed: %w", perr)
	}
	a.keyMu.Lock()
	a.setKeyLocked(newKey, newEpoch)
	a.keyMu.Unlock()
	if aerr := writeAnchorWithKey(ctx, a.logPath, newKey, newEpoch); aerr != nil {
		return RotateResult{}, fmt.Errorf("audit: post-rotation anchor write failed: %w", aerr)
	}
	return RotateResult{
		OldEpoch:          oldEpoch,
		NewEpoch:          newEpoch,
		NewKeyFingerprint: hex.EncodeToString(fp[:]),
		Completed:         true,
		Resumed:           true,
	}, nil
}
