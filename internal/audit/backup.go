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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Backup atomically copies src to <src>.bak.<timestamp> in the same directory
// (temp + fsync + rename — a crash can no longer leave a truncated .bak that a
// later restore would trust, R2-W4). The backup carries src's permission bits
// so a later restore can put them back (R2-W3); the .bak holds the same bytes
// src already exposed, so mirroring its mode leaks nothing new.
// It returns the path of the backup file on success.
func Backup(src string) (string, error) {
	content, err := os.ReadFile(src) //nolint:gosec // G304: src is an audit backup path derived from the target path, not user-controlled
	if err != nil {
		return "", fmt.Errorf("audit: backup read %s: %w", src, err)
	}

	// Nanosecond resolution so repeated writes within the same second do not
	// collide and overwrite an earlier (potentially original) backup. The
	// fixed-width fractional part keeps lexical order chronological.
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dst := fmt.Sprintf("%s.bak.%s", src, stamp)

	if err := atomicWriteFile(dst, content, sourceMode(src)); err != nil {
		return "", fmt.Errorf("audit: backup write %s: %w", dst, err)
	}
	return dst, nil
}

// BackupWithChain atomically copies src to a <src>.bak.<timestamp> file (same
// as Backup) and additionally appends a signed chain entry recording the backup
// path and SHA-256 of the backed-up content (AUD-01 / A9).
//
// If the chain-entry Append fails, the just-created .bak file is removed
// (rollback) and the Append error is returned. The caller's mutation must also
// abort on this error to preserve the append-before-write audit ordering.
func BackupWithChain(ctx context.Context, src string, sa *SignedAudit) (string, error) {
	content, err := os.ReadFile(src) //nolint:gosec // G304: src is an audit backup path derived from the target path, not user-controlled
	if err != nil {
		return "", fmt.Errorf("audit: backup read %s: %w", src, err)
	}

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dst := fmt.Sprintf("%s.bak.%s", src, stamp)

	if err := atomicWriteFile(dst, content, sourceMode(src)); err != nil {
		return "", fmt.Errorf("audit: backup write %s: %w", dst, err)
	}

	// AUD-01: record the backup path and content hash in the signed chain.
	diffHash := sha256.Sum256(content)
	if aerr := sa.Append(ctx, SignInput{Title: "backup", DiffHash: diffHash}, dst, false); aerr != nil {
		// Rollback: remove the orphaned .bak file before returning the error.
		_ = os.Remove(dst)
		return "", fmt.Errorf("audit: backup chain-entry failed (backup rolled back): %w", aerr)
	}
	return dst, nil
}

// BackupsFromChain returns chain entries for target by walking the signed audit
// log and filtering entries where Op="backup" and the Target is one of target's
// own ".bak.<stamp>" sidecars. This is the authoritative backup-selection path
// (AUD-01 / D-02): chain-recorded entries are the source of truth, not
// filesystem glob order.
//
// R2-I1: the match is target+".bak." (not a bare prefix), so backups of a
// sibling path like "/a/b2" can never be claimed for target "/a/b".
//
// logPath is the path of the signed audit log. target is the original source
// file path (not the .bak path). A missing or empty log returns (nil, nil).
func BackupsFromChain(logPath, target string) ([]Entry, error) {
	entries, err := ReadLog(logPath)
	if err != nil {
		return nil, err
	}
	var result []Entry
	for _, e := range entries {
		if e.Op == "backup" && strings.HasPrefix(e.Target, target+".bak.") {
			result = append(result, e)
		}
	}
	return result, nil
}

// Restore copies backupPath over dst. Both paths must share the same directory
// (path traversal is rejected). dst must be an absolute path.
func Restore(dst, backupPath string) error {
	// Reject traversal: clean both paths and verify they share the same dir.
	cleanDst := filepath.Clean(dst)
	cleanBak := filepath.Clean(backupPath)

	if !strings.HasPrefix(cleanDst, "/") {
		return fmt.Errorf("audit: restore dst must be absolute, got %q", dst)
	}
	if filepath.Dir(cleanBak) != filepath.Dir(cleanDst) {
		return fmt.Errorf("audit: backup %q and dst %q must be in the same directory", backupPath, dst)
	}

	content, err := os.ReadFile(cleanBak) //nolint:gosec // G304: cleanBak is a filepath.Clean of an internally-derived backup path, not user-controlled
	if err != nil {
		return fmt.Errorf("audit: restore read backup %s: %w", cleanBak, err)
	}

	// R2-W3: unique O_EXCL temp (no predictable dst+".tmp" an attacker can
	// pre-plant as a symlink) and the backup's recorded permission bits — a
	// 0644 original comes back 0644, an unknown mode falls back to 0600.
	return atomicRestoreWrite(cleanDst, content, sourceMode(cleanBak))
}
