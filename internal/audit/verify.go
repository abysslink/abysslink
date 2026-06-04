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

	// CR-02: only fetch the HMAC key when a keychain is actually present.
	// fetchHMACKey calls kc.Get, which panics on a nil interface.
	var key []byte
	if kc != nil {
		if key, err = fetchHMACKey(ctx, kc); err != nil {
			return VerifyResult{}, err
		}
	}

	result := walkChain(rawLines, entries, key)
	if !result.OK {
		return result, nil
	}
	return verifyAnchor(ctx, logPath, rawLines, entries, key, kc, result)
}

// walkChain validates each entry's prev_hash link and (when key != nil) HMAC
// signature, returning the first failure or an OK result with sig counts. A nil
// key skips HMAC checks (documented fail-open-chain-walk; CR-02).
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
func walkChain(rawLines [][]byte, entries []Entry, key []byte) VerifyResult {
	result := VerifyResult{OK: true, At: -1}
	chainStarted := false
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

		expectedPrev := genesisMarker
		if i > 0 {
			sum := sha256.Sum256(rawLines[i-1])
			expectedPrev = hex.EncodeToString(sum[:])
		}
		if e.PrevHash != expectedPrev {
			return VerifyResult{OK: false, At: i, Reason: "prev_hash mismatch"}
		}

		if e.Sig == "" {
			result.SigsSkipped++
			continue
		}
		if key == nil {
			// Keychain unavailable: skip the HMAC check but record it was not
			// authenticated so callers can warn the operator.
			result.SigsSkipped++
			continue
		}
		if !verifyEntrySig(key, e) {
			return VerifyResult{OK: false, At: i, Reason: "sig mismatch"}
		}
		result.SigsVerified++
	}
	return result
}

// verifyEntrySig reconstructs the EXACT SignInput that Append signed (CR-03):
// Title == e.Op, plus Target/Time/DryRun/PrevHash, and DiffHash recovered by
// hex-decoding the stored hash. Append stores Hash = hex(in.DiffHash[:]) and
// Time as RFC3339; using the hex string or a different time precision would
// never match the signed digest.
func verifyEntrySig(key []byte, e Entry) bool {
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
	return verifyHMAC(key, in, e.Sig)
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
		// No anchor yet — still run the AUD-02 counter check below.
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
	// WR-01: when the counts match, the anchor's LastHash must equal
	// sha256(last raw line). A mismatch is a history rewrite at/below the
	// anchored length that the count check alone cannot catch.
	if anchor.EntryCount == int64(len(entries)) && len(rawLines) > 0 {
		sum := sha256.Sum256(rawLines[len(rawLines)-1])
		if anchor.LastHash != hex.EncodeToString(sum[:]) {
			return VerifyResult{OK: false, At: len(entries) - 1, Reason: "anchor last_hash mismatch (history rewrite)"}, nil
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
		// Counter LAGS the log: more signed entries exist on disk than the counter
		// recorded. Every entry was HMAC-chain-verified by the walk above, so these
		// are legitimately-signed appends the counter never caught up to — the
		// documented append-before-write crash window (a process death between the
		// JSONL append and the keychain counter bump). A log-only attacker cannot
		// forge additional chain-valid entries, so this is NEVER truncation. Degrade
		// to UNKNOWN (honest tri-state), never a false "mismatch" tamper alarm.
		result.CounterStatus = "unknown"
		result.Reason = fmt.Sprintf(
			"keychain counter %d < log entries %d (append-before-write window; counter lagging)", n, entryCount)
	default:
		result.CounterStatus = "verified"
	}
	return result
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
