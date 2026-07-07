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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/abysslink/abysslink/internal/secrets"
)

// Key epochs (ROT-01): every signed entry belongs to a key epoch. Epoch 1 is
// the original key at keychain account "audit-hmac"; epoch N>=2 keys live at
// "audit-hmac-e<N>". Old keys are RETAINED forever (never deleted) so
// pre-rotation history stays verifiable — NIST SP 800-57 separates the
// originator-usage period (signing, rotated) from the recipient-usage period
// (verification, retained). The honest security claim is therefore
// tamper-evidence against parties WITHOUT keychain access; retaining keys
// forfeits forward integrity by design (a keychain-level compromise can
// rewrite any epoch). Never claim forward security.
//
// The verifier rules encode the lessons of the journald FSS analysis
// (CVE-2023-31437/38/39, IACR 2023/867; systemd PRs #28885/#28886):
//   - an entry's declared epoch must equal the epoch established by CHAIN
//     POSITION (a rotation marker is the only legal transition), never
//     trusted on its own — otherwise an attacker holding any retained key
//     reseals rewritten history under an epoch of their choosing;
//   - epochs are continuous (increment by exactly 1) so a log truncated at a
//     rotation boundary cannot masquerade as an intact shorter log;
//   - the declared epoch is covered by the HMAC input (epoch >= 2 framing),
//     closing the RFC 8725 "kid confusion" vector.
const (
	// epochPointerAccount stores the CURRENT epoch as a decimal string.
	// A dedicated pointer entry is used because KeychainStore deliberately has
	// no List primitive (dump-keychain is forbidden) and probing epoch-suffixed
	// accounts in a loop conflates "absent" with "locked" on the Linux backend.
	epochPointerAccount = "audit-hmac-epoch" // full keychain id: abysslink-audit-hmac-epoch

	// opRotate is the Op of the in-chain rotation marker. The marker is signed
	// by the OLD key under the OLD epoch's framing (TUF-style custody handoff):
	// Target carries the new epoch ("epoch:<N>") and Hash carries
	// hex(sha256(newKeyBytes)) — a fingerprint binding the successor key
	// without exposing key material (32 random bytes are not invertible).
	opRotate = "rotate-audit-hmac"

	firstEpoch = 1
)

// epochAccount returns the keychain account for an epoch's HMAC key.
// Epoch 1 keeps the historical account name so existing installs (and the
// daemon/arm consumers that read the literal "audit-hmac" account) are
// untouched by this feature shipping.
func epochAccount(epoch uint32) string {
	if epoch <= firstEpoch {
		return hmacKeyAccount
	}
	return fmt.Sprintf("%s-e%d", hmacKeyAccount, epoch)
}

// fetchHMACKeyEpoch fetches and hex-decodes the HMAC key for epoch.
// Like fetchHMACKey it is a package function so read paths can never trigger
// key generation.
func fetchHMACKeyEpoch(ctx context.Context, kc KeychainStore, epoch uint32) ([]byte, error) {
	hexKey, err := kc.Get(ctx, hmacKeyService, epochAccount(epoch))
	if err != nil {
		return nil, fmt.Errorf("audit: fetch hmac key (epoch %d): %w", epoch, err)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("audit: decode hmac key (epoch %d): %w", epoch, err)
	}
	return key, nil
}

// readEpochPointer returns the current key epoch recorded in the keychain.
// An absent pointer means the pre-rotation world: epoch 1. Any other keychain
// failure propagates (CORE-02: absence and unavailability are never conflated).
func readEpochPointer(ctx context.Context, kc KeychainStore) (uint32, error) {
	val, err := kc.Get(ctx, hmacKeyService, epochPointerAccount)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return firstEpoch, nil
		}
		return 0, fmt.Errorf("audit: read epoch pointer: %w", err)
	}
	n, perr := strconv.ParseUint(strings.TrimSpace(val), 10, 32)
	if perr != nil || n < firstEpoch {
		return 0, fmt.Errorf("audit: parse epoch pointer %q: %w", val, perr)
	}
	return uint32(n), nil
}

// writeEpochPointer records the current key epoch in the keychain.
func writeEpochPointer(ctx context.Context, kc KeychainStore, epoch uint32) error {
	if err := kc.Set(ctx, hmacKeyService, epochPointerAccount, strconv.FormatUint(uint64(epoch), 10)); err != nil {
		return fmt.Errorf("audit: write epoch pointer: %w", err)
	}
	return nil
}

// signBytesEpoch is the epoch-aware HMAC input. Epoch 1 produces the EXACT
// legacy framing byte-for-byte, so every pre-rotation chain keeps verifying.
// Epoch >= 2 appends the epoch as a fixed-width big-endian uint32 AFTER the
// legacy framing (append-only evolution): the declared epoch is thereby
// MAC-covered, so stripping or altering the key_epoch field of a post-rotation
// entry breaks its signature instead of downgrading it (RFC 8725 lesson).
func signBytesEpoch(in SignInput, epoch uint32) []byte {
	b := signBytes(in)
	if epoch <= firstEpoch {
		return b
	}
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	return append(b, e[:]...)
}

// effectiveEpoch returns the epoch an entry claims: absent/zero key_epoch
// means epoch 1 (all pre-rotation entries).
func effectiveEpoch(e Entry) uint32 {
	if e.KeyEpoch < firstEpoch {
		return firstEpoch
	}
	return e.KeyEpoch
}

// rotationTargetEpoch parses the new epoch from a rotation marker's Target
// ("epoch:<N>"). Returns 0 when the target is not a well-formed marker target.
func rotationTargetEpoch(target string) uint32 {
	rest, ok := strings.CutPrefix(target, "epoch:")
	if !ok {
		return 0
	}
	n, err := strconv.ParseUint(rest, 10, 32)
	if err != nil || n < firstEpoch+1 {
		return 0
	}
	return uint32(n)
}

// tailEpoch returns the epoch in effect AFTER the last entry of the log: the
// last entry's effective epoch, or — when the last entry is a valid-shaped
// rotation marker — the marker's target epoch. Empty/missing log => epoch 1.
// Writers use this to fail closed on a half-completed rotation (marker
// appended, pointer not yet advanced) instead of appending entries whose
// declared epoch contradicts the chain (which the verifier would flag).
func tailEpoch(logPath string) (uint32, error) {
	last, err := readLastNonEmptyLine(logPath)
	if err != nil {
		return 0, err
	}
	if len(last) == 0 {
		return firstEpoch, nil
	}
	var e Entry
	if uerr := json.Unmarshal(last, &e); uerr != nil {
		return 0, fmt.Errorf("audit: parse log line: %w", uerr)
	}
	if e.Op == opRotate {
		if t := rotationTargetEpoch(e.Target); t != 0 {
			return t, nil
		}
	}
	return effectiveEpoch(e), nil
}

// epochKeys is a lazy per-epoch key cache for the verifier. fetch returns
// (key, false, nil) on success, (nil, true, nil) when the keychain
// definitively reports the epoch's key absent (ErrNotFound — the
// INDETERMINATE input), and (nil, false, err) on any other keychain failure.
type epochKeys struct {
	kc   KeychainStore
	keys map[uint32][]byte
}

func newEpochKeys(kc KeychainStore) *epochKeys {
	return &epochKeys{kc: kc, keys: make(map[uint32][]byte)}
}

func (ek *epochKeys) fetch(ctx context.Context, epoch uint32) (key []byte, missing bool, err error) {
	if k, ok := ek.keys[epoch]; ok {
		return k, false, nil
	}
	if ek.kc == nil {
		return nil, true, nil
	}
	k, ferr := fetchHMACKeyEpoch(ctx, ek.kc, epoch)
	if ferr != nil {
		if errors.Is(ferr, secrets.ErrNotFound) {
			return nil, true, nil
		}
		return nil, false, ferr
	}
	ek.keys[epoch] = k
	return k, false, nil
}

// EpochStatus reports the audit chain's rotation health for the doctor
// sec-audit-epoch check (ROT-03). It is read-only and never mutates keychain
// or log state.
type EpochStatus struct {
	PointerEpoch uint32 // current epoch recorded in the keychain
	TailEpoch    uint32 // epoch in force at the chain tail
	Incomplete   bool   // tail is ahead of the pointer (half-finished rotation)
}

// ReadEpochStatus resolves the keychain epoch pointer and the chain-tail epoch
// so the doctor can report rotation health. A nil keychain or a definitively
// absent pointer both read as epoch 1 (pre-rotation). Non-absence keychain
// failures propagate (CORE-02).
func ReadEpochStatus(ctx context.Context, logPath string, kc KeychainStore) (EpochStatus, error) {
	pointer := uint32(firstEpoch)
	if kc != nil {
		p, err := readEpochPointer(ctx, kc)
		if err != nil {
			return EpochStatus{}, err
		}
		pointer = p
	}
	tail, err := tailEpoch(logPath)
	if err != nil {
		return EpochStatus{}, err
	}
	return EpochStatus{
		PointerEpoch: pointer,
		TailEpoch:    tail,
		Incomplete:   tail > pointer,
	}, nil
}
