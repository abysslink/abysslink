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
	"path/filepath"
	"sort"
	"strings"
)

// ReadLog parses the audit log at logPath into Entry records. A missing log is
// not an error — it returns an empty slice.
func ReadLog(logPath string) ([]Entry, error) {
	f, err := os.Open(logPath) //nolint:gosec // logPath is an internal, app-controlled path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open log %s: %w", logPath, err)
	}
	defer f.Close() //nolint:errcheck // errcheck: close error on read-only/append file handle is non-actionable; data durability handled by explicit Sync where required

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("audit: parse log line: %w", err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: read log %s: %w", logPath, err)
	}
	return entries, nil
}

// MutatedTargets returns the distinct file paths abysslink has written (op
// "write", non-dry-run), in first-seen order.
func MutatedTargets(logPath string) ([]string, error) {
	entries, err := ReadLog(logPath)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var targets []string
	for _, e := range entries {
		if e.Op != "write" || e.DryRun {
			continue
		}
		if !seen[e.Target] {
			seen[e.Target] = true
			targets = append(targets, e.Target)
		}
	}
	return targets, nil
}

// Backups returns the backup files for target (the <target>.bak.<timestamp>
// sidecars), sorted oldest-first. The timestamp format sorts chronologically by
// lexical order, so index 0 is the earliest (pre-abysslink) content.
func Backups(target string) ([]string, error) {
	matches, err := filepath.Glob(target + ".bak.*")
	if err != nil {
		return nil, fmt.Errorf("audit: glob backups for %s: %w", target, err)
	}
	sort.Strings(matches)
	return matches, nil
}

// findChainEntry walks the signed log at logPath for an Op="backup" entry
// whose Target equals cleanBak. Returns nil if not found.
func findChainEntry(logPath, cleanBak string) (*Entry, error) {
	entries, err := ReadLog(logPath)
	if err != nil {
		return nil, fmt.Errorf("audit: restore: read chain: %w", err)
	}
	for i := range entries {
		if entries[i].Op == "backup" && entries[i].Target == cleanBak {
			e := entries[i]
			return &e, nil
		}
	}
	return nil, nil
}

// verifyBackupHash recomputes sha256(content) and checks it against chainEntry.Hash.
func verifyBackupHash(content []byte, chainEntry *Entry, cleanBak string) error {
	got := sha256.Sum256(content)
	if hex.EncodeToString(got[:]) != chainEntry.Hash {
		return fmt.Errorf("audit: restore refused: backup content hash mismatch for %q (chain entry present but content modified)", cleanBak)
	}
	return nil
}

// atomicRestoreWrite writes content to dst via a tmp+rename sequence (0o600).
func atomicRestoreWrite(cleanDst string, content []byte) error {
	tmp := cleanDst + ".tmp"
	if werr := os.WriteFile(tmp, content, 0o600); werr != nil { //nolint:gosec // G304: tmp is an internally-derived restore temp path; 0o600 enforces owner-only perms
		return fmt.Errorf("audit: restore write tmp %s: %w", tmp, werr)
	}
	if rerr := os.Rename(tmp, cleanDst); rerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: restore rename %s → %s: %w", tmp, cleanDst, rerr)
	}
	return nil
}

// RestoreGated is the AUD-01 chain-verified restore path. It refuses to write
// backupPath over dst unless a signed chain entry exists matching backupPath +
// sha256(content), or acceptUnverified is true.
//
// Gate logic (D-01, D-02):
//   - Walk the signed chain for an Op="backup" entry with Target==cleanBak.
//   - If no matching entry found and acceptUnverified==false: return error.
//   - If a matching entry found: recompute sha256(content) and verify it matches
//     the stored hash. Hash mismatch → return error (content modified).
//   - If acceptUnverified==true and no chain entry: restore is allowed but the
//     restore is recorded as a "restore-unverified" non-OK audit entry.
//
// Both dst and backupPath must be absolute; they must share the same directory
// (path traversal is rejected). This is the only bypass for unchained backups;
// the bypass itself is auditable.
func RestoreGated(ctx context.Context, dst, backupPath string, sa *SignedAudit, acceptUnverified bool) error {
	cleanDst := filepath.Clean(dst)
	cleanBak := filepath.Clean(backupPath)

	if !strings.HasPrefix(cleanDst, "/") {
		return fmt.Errorf("audit: restore dst must be absolute, got %q", dst)
	}
	if filepath.Dir(cleanBak) != filepath.Dir(cleanDst) {
		return fmt.Errorf("audit: backup %q and dst %q must be in the same directory", backupPath, dst)
	}

	// AUD-01 / D-02: walk the signed chain for an Op="backup" entry matching cleanBak.
	chainEntry, err := findChainEntry(sa.LogPath(), cleanBak)
	if err != nil {
		return err
	}
	if chainEntry == nil && !acceptUnverified {
		return fmt.Errorf("audit: restore refused: no chain entry for %q — pass --accept-unverified-backup to override", cleanBak)
	}

	content, rerr := os.ReadFile(cleanBak) //nolint:gosec // G304: cleanBak is a filepath.Clean of an internally-derived backup path, not user-controlled
	if rerr != nil {
		return fmt.Errorf("audit: restore read backup %s: %w", cleanBak, rerr)
	}

	// If a chain entry was found, verify content hash matches.
	if chainEntry != nil {
		if verr := verifyBackupHash(content, chainEntry, cleanBak); verr != nil {
			return verr
		}
	}

	if werr := atomicRestoreWrite(cleanDst, content); werr != nil {
		return werr
	}

	// AUD-01 / D-01: record the unverified restore as a non-OK audit entry.
	if acceptUnverified && chainEntry == nil {
		diffHash := sha256.Sum256(content)
		// Non-fatal: the restore succeeded; log the audit failure as a warning.
		// The caller can see dst was changed even if this entry is missing.
		_ = sa.Append(ctx, SignInput{Title: "restore-unverified", DiffHash: diffHash}, cleanDst, false)
	}
	return nil
}

// ReverseAction records what reversing a single mutated target did (or would do).
type ReverseAction struct {
	Target string
	Action string // "restore" | "delete" | "skip"
	Backup string // backup file used for a restore (empty otherwise)
	Hash   string // SHA-256 of the file content after the action ("" if removed/absent)
	Err    error  // non-nil if the action failed
}

// PlanReverse computes how to undo every mutation in the audit log: a target
// with a backup is restored to its earliest (pre-abysslink) content; a target
// abysslink created (no backup) is deleted; an already-absent target is skipped.
func PlanReverse(logPath string) ([]ReverseAction, error) {
	targets, err := MutatedTargets(logPath)
	if err != nil {
		return nil, err
	}

	plan := make([]ReverseAction, 0, len(targets))
	for _, t := range targets {
		baks, _ := Backups(t)
		switch {
		case len(baks) > 0:
			plan = append(plan, ReverseAction{Target: t, Action: "restore", Backup: baks[0]})
		default:
			if _, statErr := os.Stat(t); statErr == nil {
				plan = append(plan, ReverseAction{Target: t, Action: "delete"})
			} else {
				plan = append(plan, ReverseAction{Target: t, Action: "skip"})
			}
		}
	}
	return plan, nil
}

// Reverse undoes every mutation recorded in the audit log. When dryRun is true
// it computes the plan and the resulting hashes without touching the
// filesystem. On a real run it restores or deletes each target and removes the
// now-redundant sidecar backups, returning a manifest of what happened. Errors
// on individual targets are recorded per-action; the overall walk continues.
func Reverse(logPath string, dryRun bool) ([]ReverseAction, error) {
	plan, err := PlanReverse(logPath)
	if err != nil {
		return nil, err
	}

	for i := range plan {
		a := &plan[i]
		switch a.Action {
		case "restore":
			if dryRun {
				if content, rerr := os.ReadFile(a.Backup); rerr == nil { //nolint:gosec // G304: a.Backup is a path from a trusted audit-log entry written by abysslink, not user input
					a.Hash = HashOf(content)
				}
				continue
			}
			if rerr := Restore(a.Target, a.Backup); rerr != nil {
				a.Err = rerr
				continue
			}
			if content, rerr := os.ReadFile(a.Target); rerr == nil { //nolint:gosec // G304: a.Target is a path from a trusted audit-log entry written by abysslink, not user input
				a.Hash = HashOf(content)
			}
			// The original content is back in place; drop the redundant backups.
			if baks, gerr := Backups(a.Target); gerr == nil {
				for _, b := range baks {
					_ = os.Remove(b)
				}
			}
		case "delete":
			if dryRun {
				continue
			}
			if rerr := os.Remove(a.Target); rerr != nil && !os.IsNotExist(rerr) {
				a.Err = rerr
			}
		}
	}
	return plan, nil
}
