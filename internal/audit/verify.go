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
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// VerifyResult reports the outcome of a chain walk. OK is true only when every
// signed entry chains and verifies; At is the index of the first bad entry (-1
// when OK). TruncationDetected is set when the (HMAC-validated) anchor records
// more entries than the log currently holds, OR when the keychain counter
// disagrees with the log entry count (AUD-02 / A10). SigsVerified counts
// entries whose HMAC signature was checked and matched; SigsSkipped counts
// entries whose signature could not be authenticated (legacy/unsigned entries,
// or any signed entry when the keychain is unavailable so HMAC checks are
// skipped).
//
// CounterStatus reports the AUD-02 keychain counter check (D-04 tri-state
// honesty rule — mirrors the probeOK pattern):
//   - "verified"  — keychain counter matches log entry count
//   - "mismatch"  — counter disagrees with entry count (tail-truncation)
//   - "unknown"   — counter absent or keychain unavailable (NEVER coerced to PASS)
//   - ""          — pre-AUD-02 log (no counter was ever written)
type VerifyResult struct {
	OK                 bool
	At                 int
	Reason             string
	TruncationDetected bool
	CounterStatus      string // "verified" | "unknown" | "mismatch" | "" (pre-AUD-02 log)
	SigsVerified       int
	SigsSkipped        int
	// Indeterminate marks a fail-closed-but-not-tamper verdict (ROT): an epoch
	// key the chain legitimately references is missing from the keychain, so a
	// range is UNVERIFIABLE. Distinct from tampering (CloudTrail-style
	// valid/invalid/not-found separation): callers must refuse a VALID verdict
	// (OK=false) but must not report TAMPERED — cmd_audit maps this to exit 1,
	// not 2.
	Indeterminate bool

	// lastEpoch is the key epoch in force at the end of the walk (chain tail).
	// Package-internal: Verify's boundary-truncation check (V5) compares it to
	// the keychain epoch pointer.
	lastEpoch uint32
}

// Verify walks the full log and the anchor. It is a read-only path and holds no
// mutex. Pre-chain legacy entries (empty PrevHash) are skipped gracefully so
// existing unsigned v1/v2 logs still verify.
//
// kc may be nil when no keychain backend is available. In that case Verify still
// walks the hash chain (and validates anchor structure where possible) but
// SKIPS the per-entry HMAC check rather than dereferencing a nil keychain — this
// honours the documented "verify can still walk the chain with a nil key"
// contract (cmd_audit.go) and the "no panics in normal control flow" hard rule.
// Skipped signatures are surfaced via VerifyResult.SigsSkipped so callers do not
// mistake an unverified walk for a fully authenticated one.
func Verify(ctx context.Context, logPath string, kc KeychainStore) (VerifyResult, error) {
	rawLines, entries, err := scanRawAndEntries(logPath)
	if err != nil {
		return VerifyResult{}, err
	}

	// CR-02: only fetch HMAC keys when a keychain is actually present.
	//
	// R2: a definitively-absent key (ErrNotFound) is NOT an error — it is the
	// legitimate "no chain was ever signed" state (key creation is lazy since
	// R2-12). It degrades to key == nil, exactly like a nil keychain. Any other
	// fetch failure (keychain locked, dbus down) still hard-errors.
	//
	// ROT-01: keys are per-epoch; the walk resolves them lazily by CHAIN
	// POSITION through this cache. "key" below is the CURRENT (pointer) epoch's
	// key — the "has any signing ever happened" signal the anchor logic uses.
	keys := newEpochKeys(kc)
	var key []byte
	var pointerEpoch uint32 = firstEpoch
	if kc != nil {
		pointerEpoch, err = readEpochPointer(ctx, kc)
		if err != nil {
			return VerifyResult{}, err
		}
		var missing bool
		key, missing, err = keys.fetch(ctx, pointerEpoch)
		if err != nil {
			return VerifyResult{}, err
		}
		if missing {
			// Epoch 1 + no key = the legitimate "no chain was ever signed"
			// state (lazy creation, R2-12). A ROTATED pointer with a missing
			// key is nothing of the sort: a rotation completed and its key
			// vanished from the keychain. Unverifiable — fail closed, but
			// lexically distinct from tampering (V6).
			if pointerEpoch > firstEpoch {
				return VerifyResult{
					OK: false, At: -1, Indeterminate: true,
					Reason: fmt.Sprintf("keychain records epoch %d but its key is missing (unverifiable)", pointerEpoch),
				}, nil
			}
			key = nil
		}
	}

	result := walkChain(ctx, rawLines, entries, keys, key != nil)
	if !result.OK {
		return result, nil
	}

	// V5 (CVE-2023-31438 boundary truncation): the keychain pointer cannot be
	// AHEAD of the chain. If a rotation was completed (pointer advanced) but
	// the log ends before its rotation marker, the tail was cut at the epoch
	// boundary — a truncation the per-entry checks alone cannot see.
	if kc != nil && key != nil && pointerEpoch > result.lastEpoch {
		result.OK = false
		result.TruncationDetected = true
		result.Reason = fmt.Sprintf(
			"log ends at key epoch %d but keychain records epoch %d (truncation at rotation boundary)",
			result.lastEpoch, pointerEpoch)
		return result, nil
	}

	return verifyAnchor(ctx, logPath, rawLines, entries, key, kc, result)
}

// walkChain validates each entry's prev_hash link and (when keys are
// available) HMAC signature, returning the first failure or an OK result with
// sig counts. hasKeys=false skips HMAC checks (documented
// fail-open-chain-walk; CR-02) while still enforcing every STRUCTURAL epoch
// rule below.
//
// CR-01 (iteration 2): the legacy "empty prev_hash → skip link+sig" allowance is
// honoured ONLY for a CONTIGUOUS HEAD PREFIX of genuinely-unsigned v1/v2 entries.
// Genuine legacy logs are always a wholly-unsigned prefix; signed entries always
// carry a non-empty PrevHash (genesis or a hex link). Once the first signed entry
// is observed (chainStarted), any later entry with an empty PrevHash — or any
// entry carrying a Sig but no PrevHash — is a downgrade/strip attack (an attacker
// blanking prev_hash+sig on the tail to rewrite op/target/dry_run/hash undetected)
// and is REJECTED as CHAIN BROKEN. Without this, the unprotected tail entry could
// be silently downgraded to "legacy", defeating CR-03's expanded HMAC.
//
// ROT-01 epoch rules (journald FSS CVE-2023-31438/31439 lessons):
//   - the epoch in force is established by CHAIN POSITION, starting at 1; a
//     sig-valid rotation marker is the ONLY legal transition and increments it
//     by EXACTLY 1 (continuity);
//   - every entry's declared key_epoch must equal the epoch in force at its
//     position — an entry may never select its own verification key (RFC 8725);
//   - the marker's Hash must be the SHA-256 fingerprint of the keychain key for
//     the new epoch (TUF-style custody binding);
//   - an epoch key the chain legitimately references but the keychain lacks is
//     INDETERMINATE (unverifiable range, fail closed) — lexically distinct from
//     tampering.
func walkChain(ctx context.Context, rawLines [][]byte, entries []Entry, keys *epochKeys, hasKeys bool) VerifyResult {
	result := VerifyResult{OK: true, At: -1, lastEpoch: firstEpoch}
	chainStarted := false
	expectedEpoch := uint32(firstEpoch)
	for i, e := range entries {
		if e.PrevHash == "" {
			if chainStarted || e.Sig != "" {
				// A signed chain has begun (or this entry still carries a Sig):
				// a later/blanked empty prev_hash is a downgrade/strip attack,
				// not a genuine pre-chain legacy entry.
				return VerifyResult{OK: false, At: i, Reason: "CHAIN BROKEN: prev_hash stripped after chain start (tamper)"}
			}
			result.SigsSkipped++ // genuine contiguous-prefix legacy entry — skip chain/sig checks
			continue
		}
		chainStarted = true

		if bad, ok := walkChainEntry(ctx, rawLines, entries, i, keys, hasKeys, expectedEpoch, &result); !ok {
			return bad
		}
		if e.Op == opRotate {
			// Continuity is already validated in walkChainEntry; adopt the new epoch.
			expectedEpoch = rotationTargetEpoch(e.Target)
		}
		result.lastEpoch = expectedEpoch
	}
	return result
}

// walkChainEntry validates one chained entry at index i against expectedEpoch,
// updating result's sig counters. It returns (bad, false) with the failure
// verdict on any violation, or (VerifyResult{}, true) to continue. Split out of
// walkChain to keep each below the cyclomatic-complexity gate; the per-entry
// rules (prev_hash link, V2 epoch-position, V3 continuity, HMAC, V4 custody,
// V6 indeterminacy) are documented inline.
func walkChainEntry(ctx context.Context, rawLines [][]byte, entries []Entry, i int, keys *epochKeys, hasKeys bool, expectedEpoch uint32, result *VerifyResult) (VerifyResult, bool) {
	e := entries[i]

	expectedPrev := genesisMarker
	if i > 0 {
		sum := sha256.Sum256(rawLines[i-1])
		expectedPrev = hex.EncodeToString(sum[:])
	}
	if e.PrevHash != expectedPrev {
		return VerifyResult{OK: false, At: i, Reason: "prev_hash mismatch"}, false
	}

	// V2 (CVE-2023-31439): the declared epoch must equal the epoch in force at
	// this chain position. A mismatch is a reseal attempt (or a
	// stripped/duplicated epoch field), never accepted.
	if declared := effectiveEpoch(e); declared != expectedEpoch {
		return VerifyResult{OK: false, At: i, Reason: fmt.Sprintf(
			"key_epoch %d does not match chain-position epoch %d (reseal attempt)", declared, expectedEpoch)}, false
	}

	if e.Op == opRotate {
		// V3 (CVE-2023-31438): epochs are continuous — exactly +1.
		markerTarget := rotationTargetEpoch(e.Target)
		if markerTarget == 0 {
			return VerifyResult{OK: false, At: i, Reason: "malformed rotation marker target"}, false
		}
		if markerTarget != expectedEpoch+1 {
			return VerifyResult{OK: false, At: i, Reason: fmt.Sprintf(
				"rotation marker skips from epoch %d to %d (continuity violation)", expectedEpoch, markerTarget)}, false
		}
	}

	if bad, ok := walkVerifyEntrySig(ctx, e, i, keys, hasKeys, expectedEpoch, result); !ok {
		return bad, false
	}

	if e.Op == opRotate && hasKeys {
		if bad, ok := walkVerifyMarkerCustody(ctx, e, i, keys, rotationTargetEpoch(e.Target)); !ok {
			return bad, false
		}
	}
	return VerifyResult{}, true
}

// walkVerifyEntrySig performs the per-entry HMAC check under the entry's epoch,
// counting verified/skipped sigs and returning the fail-closed verdict on a
// keychain error (indeterminate), a missing epoch key (V6 indeterminate), or a
// sig mismatch (tamper).
func walkVerifyEntrySig(ctx context.Context, e Entry, i int, keys *epochKeys, hasKeys bool, epoch uint32, result *VerifyResult) (VerifyResult, bool) {
	if e.Sig == "" || !hasKeys {
		result.SigsSkipped++
		return VerifyResult{}, true
	}
	key, missing, kerr := keys.fetch(ctx, epoch)
	if kerr != nil {
		return VerifyResult{OK: false, At: i, Indeterminate: true, Reason: fmt.Sprintf(
			"keychain unavailable fetching epoch %d key: %v", epoch, kerr)}, false
	}
	if missing {
		// V6: the chain references an epoch the keychain cannot verify.
		// Unverifiable, fail closed — but NOT a tamper verdict.
		return VerifyResult{OK: false, At: i, Indeterminate: true, Reason: fmt.Sprintf(
			"epoch %d key missing from keychain (unverifiable range)", epoch)}, false
	}
	if !verifyEntrySig(key, e, epoch) {
		return VerifyResult{OK: false, At: i, Reason: "sig mismatch"}, false
	}
	result.SigsVerified++
	return VerifyResult{}, true
}

// walkVerifyMarkerCustody enforces V4: a rotation marker's Hash must be the
// SHA-256 fingerprint of the keychain's key for the NEW epoch (TUF-style
// custody binding). A missing new-epoch key is indeterminate, not tamper.
func walkVerifyMarkerCustody(ctx context.Context, e Entry, i int, keys *epochKeys, markerTarget uint32) (VerifyResult, bool) {
	newKey, missing, kerr := keys.fetch(ctx, markerTarget)
	if kerr != nil {
		return VerifyResult{OK: false, At: i, Indeterminate: true, Reason: fmt.Sprintf(
			"keychain unavailable fetching epoch %d key: %v", markerTarget, kerr)}, false
	}
	if missing {
		return VerifyResult{OK: false, At: i, Indeterminate: true, Reason: fmt.Sprintf(
			"epoch %d key missing from keychain (rotation marker unverifiable)", markerTarget)}, false
	}
	sum := sha256.Sum256(newKey)
	if e.Hash != hex.EncodeToString(sum[:]) {
		return VerifyResult{OK: false, At: i, Reason: fmt.Sprintf(
			"rotation marker key fingerprint mismatch for epoch %d", markerTarget)}, false
	}
	return VerifyResult{}, true
}

// verifyEntrySig reconstructs the EXACT SignInput that Append signed (CR-03):
// Title == e.Op, plus Target/Time/DryRun/PrevHash, and DiffHash recovered by
// hex-decoding the stored hash. Append stores Hash = hex(in.DiffHash[:]) and
// Time as RFC3339; using the hex string or a different time precision would
// never match the signed digest.
func verifyEntrySig(key []byte, e Entry, epoch uint32) bool {
	in := SignInput{
		Title:    e.Op,
		Target:   e.Target,
		Time:     e.Time.UTC().Format(time.RFC3339),
		DryRun:   e.DryRun,
		PrevHash: e.PrevHash,
	}
	raw, derr := hex.DecodeString(e.Hash)
	if derr != nil || len(raw) != len(in.DiffHash) {
		return false
	}
	copy(in.DiffHash[:], raw)
	return verifyHMACEpoch(key, in, e.Sig, epoch)
}

// verifyAnchor validates the external anchor (CR-01, WR-01) and the AUD-02
// keychain counter, folding both results into the running VerifyResult.
// ctx is threaded through from Verify for the ReadCounter keychain call.
func verifyAnchor(ctx context.Context, logPath string, rawLines [][]byte, entries []Entry, key []byte, kc KeychainStore, result VerifyResult) (VerifyResult, error) {
	anchor, err := ReadAnchor(logPath)
	if err != nil {
		return VerifyResult{}, err
	}
	if anchor == nil {
		// R2-C2: the HMAC key exists in the keychain, so at least one signed
		// append has happened — and every signed append writes the anchor under
		// the same flock. A missing anchor therefore means the anchor was
		// deleted or the whole log was replaced (e.g. with unsigned "legacy"
		// entries) to bypass verification. Treating it as "not a violation"
		// would let a filesystem-only attacker pass Verify by deleting one file.
		if key != nil {
			return VerifyResult{
				OK: false, At: -1,
				Reason: "anchor missing but HMAC key exists (anchor deleted or log replaced)",
			}, nil
		}
		// No key was ever created (pure pre-chain legacy log): no anchor is
		// expected — still run the AUD-02 counter check below.
		result = verifyCounter(ctx, kc, entries, result)
		return result, nil
	}
	// CR-01: a forged/unsigned anchor must be treated as tampering, not silently
	// trusted. When the keychain is unavailable we cannot authenticate the
	// anchor, so conservatively skip the anchor checks rather than trust an
	// unverifiable anchor.
	if key == nil {
		result.SigsSkipped++
		result.CounterStatus = "unknown" // keychain unavailable; cannot run counter check
		return result, nil
	}
	ok, verr := VerifyAnchor(logPath, kc)
	if verr != nil {
		return VerifyResult{}, verr
	}
	if !ok {
		return VerifyResult{OK: false, At: -1, Reason: "anchor HMAC invalid (forged or tampered)"}, nil
	}
	if anchor.EntryCount > int64(len(entries)) {
		result.TruncationDetected = true
	}
	// WR-01 / R2-C2: whenever the log holds AT LEAST the anchored number of
	// entries, the anchored PREFIX must end in the recorded LastHash — i.e.
	// sha256(rawLines[EntryCount-1]) must equal anchor.LastHash. The previous
	// equality-only form (EntryCount == len(entries)) left the legitimate
	// "anchor lags after appends" case completely unchecked, so an attacker
	// could replace the whole log with more-than-EntryCount forged legacy
	// entries and pass. The lag case is exactly when rawLines is LONGER than
	// the anchored prefix — the prefix itself must still match.
	if anchor.EntryCount > 0 && int64(len(rawLines)) >= anchor.EntryCount {
		sum := sha256.Sum256(rawLines[anchor.EntryCount-1])
		if anchor.LastHash != hex.EncodeToString(sum[:]) {
			return VerifyResult{OK: false, At: int(anchor.EntryCount) - 1, Reason: "anchor last_hash mismatch (history rewrite)"}, nil
		}
	}

	// AUD-02 D-04: keychain counter check for tail-truncation detection.
	// absent counter → CounterStatus="unknown" (NEVER coerced to PASS).
	// Mirrors the probeOK tri-state honesty pattern (D-04).
	result = verifyCounter(ctx, kc, entries, result)
	return result, nil
}

// verifyCounter checks the AUD-02 keychain counter against the log entry count
// and sets result.CounterStatus and result.TruncationDetected accordingly.
// It is called from verifyAnchor after all structural checks pass.
func verifyCounter(ctx context.Context, kc KeychainStore, entries []Entry, result VerifyResult) VerifyResult {
	if kc == nil {
		result.CounterStatus = "unknown" // keychain unavailable; cannot run counter check
		return result
	}
	n, found, cerr := ReadCounter(ctx, kc)
	entryCount := int64(len(entries))
	switch {
	case cerr != nil || !found:
		// Counter absent (first-use pre-AUD-02 log) or keychain error.
		// D-04: absent counter → UNKNOWN, never PASS.
		result.CounterStatus = "unknown"
	case n > entryCount:
		// Counter records MORE entries than the log holds: the keychain counter
		// (which a log-only attacker cannot touch) outran the on-disk entries.
		// This is the genuine tail-truncation signal.
		result.TruncationDetected = true
		result.CounterStatus = "mismatch"
		result.Reason = fmt.Sprintf(
			"keychain counter %d > log entries %d (tail-truncation)", n, entryCount)
	case n < entryCount:
		// Counter LAGS the log: more entries exist on disk than the counter
		// recorded. The benign cause is the append-before-write crash window —
		// a process death between the signed JSONL append and the keychain
		// counter bump. In THAT case every excess entry (index >= n) is a fully
		// HMAC-SIGNED append the counter never caught up to; a log-only attacker
		// cannot forge one because they lack the key.
		//
		// But a filesystem-only attacker CAN append an UNSIGNED, hash-chain-linked
		// entry (prev_hash is a keyless SHA-256): the walk skips its HMAC check
		// (Sig=="") and it lands beyond the counter. That is NOT the benign
		// signed-crash window, and reporting it as one would mask an injected
		// record as a lagging counter. So gate the benign message on the excess
		// being fully signed; an unsigned excess entry is surfaced distinctly.
		// Either way CounterStatus stays "unknown" (never coerced to PASS — the
		// counter genuinely can't confirm the tail), so a legitimate
		// keychain-was-down append is not falsely alarmed as tampering, while a
		// forgery no longer hides behind the crash-window wording.
		result.CounterStatus = "unknown"
		if excessHasUnsigned(entries, n) {
			result.Reason = fmt.Sprintf(
				"keychain counter %d < log entries %d and the excess includes unsigned entries — a keychain-unavailable append or an injected record (unverifiable, not confirmed benign)", n, entryCount)
		} else {
			result.Reason = fmt.Sprintf(
				"keychain counter %d < log entries %d (append-before-write window; counter lagging)", n, entryCount)
		}
	default:
		result.CounterStatus = "verified"
	}
	return result
}

// excessHasUnsigned reports whether any entry at or beyond index n (the entries
// the keychain counter never recorded) is chained-but-unsigned (PrevHash set,
// Sig empty). Such an entry is not the benign signed append-before-write crash
// window — it is either a keychain-unavailable append or a filesystem-only
// forgery, and must not be reported as a benign counter lag. n is the counter
// value (number of counted entries), so entries[n:] is the uncounted excess.
func excessHasUnsigned(entries []Entry, n int64) bool {
	if n < 0 {
		n = 0
	}
	for i := int(n); i < len(entries); i++ {
		if entries[i].PrevHash != "" && entries[i].Sig == "" {
			return true
		}
	}
	return false
}

// scanRawAndEntries reads the log, returning the raw JSONL lines (without
// newline) alongside their parsed Entry values, index-aligned. A missing log
// yields empty slices.
func scanRawAndEntries(logPath string) ([][]byte, []Entry, error) {
	f, err := os.Open(logPath) //nolint:gosec // app-controlled path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("audit: open log %s: %w", logPath, err)
	}
	defer f.Close() //nolint:errcheck // errcheck: close error on read-only/append file handle is non-actionable; data durability handled by explicit Sync where required

	var rawLines [][]byte
	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		raw := make([]byte, len(line))
		copy(raw, line)
		var e Entry
		if uerr := json.Unmarshal(raw, &e); uerr != nil {
			return nil, nil, fmt.Errorf("audit: parse log line: %w", uerr)
		}
		rawLines = append(rawLines, raw)
		entries = append(entries, e)
	}
	if serr := scanner.Err(); serr != nil {
		return nil, nil, fmt.Errorf("audit: read log %s: %w", logPath, serr)
	}
	return rawLines, entries, nil
}
