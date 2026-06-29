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
	"log/slog"
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

// atomicRestoreWrite writes content to dst with the given permission bits via
// the shared atomic temp/rename helper. R2-W3: the temp is os.CreateTemp-unique
// (the old predictable dst+".tmp" could be pre-planted as a symlink and written
// through by os.WriteFile's O_CREATE|O_TRUNC), and mode is the backup's
// recorded permission bits so a restore no longer forces 0600 onto originals
// that were 0644.
func atomicRestoreWrite(cleanDst string, content []byte, mode os.FileMode) error {
	if werr := atomicWriteFile(cleanDst, content, mode); werr != nil {
		return fmt.Errorf("audit: restore write %s: %w", cleanDst, werr)
	}
	return nil
}

// restoreChainVerified restores backupPath over dst ONLY if the backup's
// content hash matches wantHash, the SHA-256 recorded in the signed chain
// entry (CORE-06). The content is read once: the same bytes that pass the
// hash check are the bytes written to dst, so there is no verify-then-reread
// window for an attacker to swap the .bak. Path constraints mirror Restore
// (absolute dst, same directory).
func restoreChainVerified(dst, backupPath, wantHash string) error {
	cleanDst := filepath.Clean(dst)
	cleanBak := filepath.Clean(backupPath)

	if !strings.HasPrefix(cleanDst, "/") {
		return fmt.Errorf("audit: restore dst must be absolute, got %q", dst)
	}
	if filepath.Dir(cleanBak) != filepath.Dir(cleanDst) {
		return fmt.Errorf("audit: backup %q and dst %q must be in the same directory", backupPath, dst)
	}

	content, err := os.ReadFile(cleanBak) //nolint:gosec // G304: cleanBak comes from a signed chain entry written by abysslink; content is hash-verified below
	if err != nil {
		return fmt.Errorf("audit: restore read backup %s: %w", cleanBak, err)
	}
	if HashOf(content) != wantHash {
		return fmt.Errorf("audit: reverse refused: backup %q content does not match signed chain entry hash (backup modified or planted)", cleanBak)
	}
	return atomicRestoreWrite(cleanDst, content, sourceMode(cleanBak))
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
		// Rule 8 / R2-fix-9: the chain-verified restore is itself a file
		// mutation — record the intent BEFORE the write (append-before-write).
		// Best-effort: a restore is a recovery path and must not be blocked by
		// an unwritable log; failures are surfaced via slog.
		diffHash := sha256.Sum256(content)
		if aerr := sa.Append(ctx, SignInput{Title: "restore", DiffHash: diffHash}, cleanDst, false); aerr != nil {
			slog.Warn("audit: failed to record chain-verified restore in audit log", "dst", cleanDst, "err", aerr)
		}
	}

	if werr := atomicRestoreWrite(cleanDst, content, sourceMode(cleanBak)); werr != nil {
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
	Target    string
	Action    string // "restore" | "delete" | "skip"
	Backup    string // backup file used for a restore (empty otherwise)
	ChainHash string // expected SHA-256 from the signed chain entry ("" when no chain entry — glob fallback)
	Warning   string // non-empty when the backup was selected without chain attestation (CORE-06)
	Hash      string // SHA-256 of the file content after the action ("" if removed/absent)
	Err       error  // non-nil if the action failed
}

// globFallbackWarning marks a restore whose backup was selected by filesystem
// glob because the audit log contains no signed backup entry for the target.
const globFallbackWarning = "backup selected by filesystem glob (no signed chain entry for this target); content is NOT chain-verified"

// PlanReverse computes how to undo every mutation in the audit log: a target
// with a backup is restored to its earliest (pre-abysslink) content; a target
// abysslink created (no backup) is deleted; an already-absent target is skipped.
//
// CORE-06 backup selection: signed chain entries (Op="backup") are the
// authoritative source for which .bak to restore. An attacker-planted,
// lexically-first .bak file must never win over a chain-attested one. The
// filesystem glob is used ONLY when the chain has no backup entry for the
// target (e.g. legacy unsigned logs); such actions carry a Warning and an
// empty ChainHash so callers (and Reverse) know the content is unverified.
func PlanReverse(logPath string) ([]ReverseAction, error) {
	// Read the log exactly once and build both the mutated-target list and a
	// per-target index of chain-attested backups in a single pass. The previous
	// implementation called MutatedTargets (one full-log read) and then
	// BackupsFromChain (another full-log read) for *every* target, making
	// PlanReverse O(targets × log-lines): on a real log (~15k lines, ~10k
	// targets) that is ~150M json.Unmarshal calls, so uninstall — even its
	// dry-run preview — appeared to hang for minutes. This pass is O(log-lines).
	entries, err := ReadLog(logPath)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var targets []string
	// attested maps an original target to its chain-recorded backup sidecars in
	// log (chronological) order. Backup targets are "<orig>.bak.<stamp>" and the
	// stamp never contains ".bak.", so the LAST ".bak." splits orig from the
	// sidecar — equivalent to the old anchored HasPrefix(e.Target, t+".bak.")
	// match, but built once instead of re-scanned per target.
	attested := map[string][]Entry{}
	for i := range entries {
		e := entries[i]
		if e.DryRun {
			continue
		}
		switch e.Op {
		case "write":
			if !seen[e.Target] {
				seen[e.Target] = true
				targets = append(targets, e.Target)
			}
		case "backup":
			if idx := strings.LastIndex(e.Target, ".bak."); idx > 0 {
				orig := e.Target[:idx]
				attested[orig] = append(attested[orig], e)
			}
		}
	}

	plan := make([]ReverseAction, 0, len(targets))
	for _, t := range targets {
		attested := attested[t]

		switch {
		case len(attested) > 0:
			// Earliest chain-recorded backup = pre-abysslink content. The
			// chain hash travels with the action so Reverse can refuse a
			// tampered .bak (verifyBackupHash) before restoring.
			plan = append(plan, ReverseAction{
				Target:    t,
				Action:    "restore",
				Backup:    attested[0].Target,
				ChainHash: attested[0].Hash,
			})
		default:
			baks, _ := Backups(t)
			if len(baks) > 0 {
				// CORE-06 fallback: no chain entry exists for this target —
				// glob selection is the only option, flagged as unverified.
				plan = append(plan, ReverseAction{
					Target:  t,
					Action:  "restore",
					Backup:  baks[0],
					Warning: globFallbackWarning,
				})
			} else if _, statErr := os.Stat(t); statErr == nil {
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

	// Rule 8 / R2-fix-9: reversal mutations (restores and deletions) are file
	// mutations like any other and get audit entries. The writer is the
	// chain-aware *Audit (R2-C1), so entries are signed when the log carries an
	// active chain. Entries are best-effort: reversal is the operator's
	// recovery path and must not be blocked by an unwritable audit log.
	w := New(logPath)

	for i := range plan {
		a := &plan[i]
		switch a.Action {
		case "restore":
			reverseRestore(w, a, dryRun)
		case "delete":
			if dryRun {
				continue
			}
			// Record the deletion intent before removing (append-before-write).
			if aerr := w.Append("delete", a.Target, nil, false); aerr != nil {
				slog.Warn("audit: failed to record reverse deletion in audit log", "target", a.Target, "err", aerr)
			}
			if rerr := os.Remove(a.Target); rerr != nil && !os.IsNotExist(rerr) {
				a.Err = rerr
			}
		}
	}
	return plan, nil
}

// reverseRestore executes (or dry-runs) a single "restore" action in place,
// recording the result hash and any error on a. Chain-attested backups
// (a.ChainHash != "") are hash-verified before restoring (CORE-06). On a real
// run the restore is recorded in the audit log via w (best-effort, Rule 8).
func reverseRestore(w *Audit, a *ReverseAction, dryRun bool) {
	if dryRun {
		if content, rerr := os.ReadFile(a.Backup); rerr == nil { //nolint:gosec // G304: a.Backup is a path from a trusted audit-log entry written by abysslink, not user input
			a.Hash = HashOf(content)
			// CORE-06: surface a chain-hash mismatch in the dry-run plan so
			// the operator sees the refusal before a real run.
			if a.ChainHash != "" && a.Hash != a.ChainHash {
				a.Err = fmt.Errorf("audit: reverse refused: backup %q content does not match signed chain entry hash (backup modified or planted)", a.Backup)
			}
		}
		return
	}
	// Rule 8 / R2-fix-9: record the restore intent before mutating the target.
	// The hash records the backup content being restored. Best-effort — see
	// Reverse for the rationale.
	if content, rerr := os.ReadFile(a.Backup); rerr == nil { //nolint:gosec // G304: a.Backup is a path from a trusted audit-log entry written by abysslink, not user input
		if aerr := w.Append("restore", a.Target, content, false); aerr != nil {
			slog.Warn("audit: failed to record reverse restore in audit log", "target", a.Target, "err", aerr)
		}
	}
	// CORE-06: when the backup is chain-attested, verify its content hash
	// against the signed chain entry in the same read that feeds the restore
	// — a planted or modified .bak is refused.
	if a.ChainHash != "" {
		if rerr := restoreChainVerified(a.Target, a.Backup, a.ChainHash); rerr != nil {
			a.Err = rerr
			return
		}
	} else if rerr := Restore(a.Target, a.Backup); rerr != nil {
		a.Err = rerr
		return
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
}
