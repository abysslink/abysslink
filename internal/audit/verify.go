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
)

// VerifyResult reports the outcome of a chain walk. OK is true only when every
// signed entry chains and verifies; At is the index of the first bad entry (-1
// when OK). TruncationDetected is set when the anchor records more entries than
// the log currently holds.
type VerifyResult struct {
	OK                 bool
	At                 int
	Reason             string
	TruncationDetected bool
}

// Verify walks the full log and the anchor. It is a read-only path and holds no
// mutex. Pre-chain legacy entries (empty PrevHash) are skipped gracefully so
// existing unsigned v1/v2 logs still verify.
func Verify(ctx context.Context, logPath string, kc KeychainStore) (VerifyResult, error) {
	rawLines, entries, err := scanRawAndEntries(logPath)
	if err != nil {
		return VerifyResult{}, err
	}

	key, err := fetchHMACKey(ctx, kc)
	if err != nil {
		return VerifyResult{}, err
	}

	for i, e := range entries {
		if e.PrevHash == "" {
			continue // pre-chain legacy entry — skip chain/sig checks
		}

		expectedPrev := genesisMarker
		if i > 0 {
			sum := sha256.Sum256(rawLines[i-1])
			expectedPrev = hex.EncodeToString(sum[:])
		}
		if e.PrevHash != expectedPrev {
			return VerifyResult{OK: false, At: i, Reason: "prev_hash mismatch"}, nil
		}

		if e.Sig != "" {
			// Reconstruct the EXACT SignInput that Append signed: Title == e.Op
			// and DiffHash is the [32]byte recovered by hex-decoding the stored
			// hash. Append stores Hash = hex(in.DiffHash[:]); hashing that hex
			// string instead would never match the signed digest.
			in := SignInput{Title: e.Op}
			raw, derr := hex.DecodeString(e.Hash)
			if derr != nil || len(raw) != len(in.DiffHash) {
				return VerifyResult{OK: false, At: i, Reason: "sig mismatch"}, nil
			}
			copy(in.DiffHash[:], raw)
			if !verifyHMAC(key, in, e.Sig) {
				return VerifyResult{OK: false, At: i, Reason: "sig mismatch"}, nil
			}
		}
	}

	result := VerifyResult{OK: true, At: -1}
	anchor, err := ReadAnchor(logPath)
	if err != nil {
		return VerifyResult{}, err
	}
	if anchor != nil && anchor.EntryCount > int64(len(entries)) {
		result.TruncationDetected = true
	}
	return result, nil
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
	defer f.Close() //nolint:errcheck

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
