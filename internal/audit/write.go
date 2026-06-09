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
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile is the sole authorised path for modules to mutate a file on disk.
// It backs up any existing file at path, writes content atomically (temp file +
// rename), and records the mutation in the audit log. Only the SHA-256 of
// content is logged — never the content itself — so it is safe for files that
// may contain secrets. When dryRun is true no file is written or backed up, but
// the intended mutation is still recorded in the audit log.
//
// CORE-03 hardening:
//   - the whole backup+write sequence runs under the same cross-process flock
//     the signed path uses (sibling <log>.lock), so concurrent writers to the
//     same target serialise instead of racing;
//   - the temp file is os.CreateTemp-derived (unique name, O_EXCL), so
//     concurrent writers cannot clobber each other's temp and an attacker
//     cannot pre-plant a symlink at a predictable temp path;
//   - a symlink at the target path is refused outright (os.Lstat). NOTE: this
//     is a check-then-act sequence — a symlink swapped in AFTER the Lstat is
//     not detected. The residual race is bounded: os.Rename replaces the
//     destination inode itself (it never follows a destination symlink), so
//     the rename cannot be redirected; the exposure is limited to Backup
//     reading through a freshly swapped symlink.
//
// CORE-07: the audit entry is appended BEFORE the physical write (matching
// SignedAudit). A crash between the append and the rename leaves recorded
// intent without the effect — never an unrecorded mutation.
func (a *Audit) WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error {
	if dryRun {
		return a.Append("write", path, content, true)
	}

	// CORE-03: serialise with every other audit writer (signed or unsigned)
	// via the shared OS flock on the sibling lock file. flock conflicts apply
	// across separate open file descriptions, so this also serialises two
	// goroutines using the same (or different) *Audit in one process.
	lockFD, lerr := acquireAuditLock(a.logPath)
	if lerr != nil {
		return fmt.Errorf("audit: acquire process lock: %w", lerr)
	}
	defer releaseAuditLock(lockFD)

	// CORE-03: refuse to operate on a symlink target. Writing "through" a
	// symlink would back up and replace a file outside the audited path.
	// (See the doc comment for the residual check-then-act window.)
	fi, statErr := os.Lstat(path)
	fileExists := statErr == nil
	if fileExists && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit: refusing to write %s: target is a symlink", path)
	}

	// CORE-07: append-before-write. Record the intent first so a crash after
	// this point leaves an audit record of the (possibly incomplete) mutation.
	if err := a.Append("write", path, content, false); err != nil {
		return err
	}

	// Back up an existing file before overwriting it so the change is reversible.
	if fileExists {
		if _, bErr := Backup(path); bErr != nil {
			return fmt.Errorf("audit: backup before write %s: %w", path, bErr)
		}
	}

	// CORE-03: unique, O_EXCL-created temp in the target's directory (rename
	// stays on one device; no predictable temp name to clobber or pre-link).
	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.abysslink.tmp")
	if err != nil {
		return fmt.Errorf("audit: create temp for %s: %w", path, err)
	}
	tmp := tmpFile.Name()
	_, werr := tmpFile.Write(content)
	if cerr := tmpFile.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: write temp %s: %w", tmp, werr)
	}
	if cerr := os.Chmod(tmp, perm); cerr != nil { //nolint:gosec // perm supplied by caller; tmp is os.CreateTemp-derived, app-controlled
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: chmod temp %s: %w", tmp, cerr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// DefaultLogPath returns the canonical audit-log path under XDG_STATE_HOME
// (default ~/.local/state/abysslink/audit.log) and ensures its parent directory
// exists. Callers pass the result to New.
func DefaultLogPath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("audit: home dir: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "abysslink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "audit.log"), nil
}
