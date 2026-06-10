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
// intent without the effect — never an unrecorded mutation. The append is
// fsynced (R2-W4) so a crash cannot persist the rename while losing the entry.
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
	// appendLocked is chain-aware (R2-C1): it signs when the log carries an
	// active signed chain, keeping the unsigned writer from bricking Verify.
	if err := a.appendLocked("write", path, content, false); err != nil {
		return err
	}

	// Back up an existing file before overwriting it so the change is reversible.
	if fileExists {
		if _, bErr := Backup(path); bErr != nil {
			return fmt.Errorf("audit: backup before write %s: %w", path, bErr)
		}
	}

	return atomicWriteFile(path, content, perm)
}

// atomicWriteFile writes content to path atomically and durably (R2-W4/E2):
// a unique O_EXCL temp in path's directory (so the rename stays on one device
// and no predictable temp name can be pre-linked), fsync, chmod, rename, then
// a best-effort fsync of the directory. This is the single shared
// temp/chmod/rename implementation for every physical write in this package.
func atomicWriteFile(path string, content []byte, perm os.FileMode) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.abysslink.tmp")
	if err != nil {
		return fmt.Errorf("audit: create temp for %s: %w", path, err)
	}
	if _, werr := tmpFile.Write(content); werr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return fmt.Errorf("audit: write temp %s: %w", tmpFile.Name(), werr)
	}
	return finalizeTemp(tmpFile, path, perm)
}

// finalizeTemp fsyncs and closes tmpFile, chmods it to perm, renames it over
// path, and best-effort-fsyncs the containing directory. On any error the temp
// file is removed. tmpFile must live in path's directory.
func finalizeTemp(tmpFile *os.File, path string, perm os.FileMode) error {
	tmp := tmpFile.Name()
	// R2-W4: sync the temp before the rename so a crash cannot promote an
	// empty/truncated file into place.
	serr := tmpFile.Sync()
	if cerr := tmpFile.Close(); serr == nil {
		serr = cerr
	}
	if serr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: sync temp %s: %w", tmp, serr)
	}
	if cerr := os.Chmod(tmp, perm); cerr != nil { //nolint:gosec // perm supplied by caller; tmp is os.CreateTemp-derived, app-controlled
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: chmod temp %s: %w", tmp, cerr)
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: rename %s → %s: %w", tmp, path, rerr)
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir best-effort-fsyncs a directory so a just-completed rename survives a
// crash. Failures are ignored: not every filesystem supports directory fsync,
// and the rename itself already succeeded.
func syncDir(dir string) {
	d, err := os.Open(dir) //nolint:gosec // dir is derived from an app-controlled target path
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// appendLineSynced opens logPath in append mode, writes line, and fsyncs before
// closing (R2-W4: the audit protocol's append-before-write ordering is only
// crash-safe if the appended intent entry is durable).
func appendLineSynced(logPath string, line []byte) error {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: logPath is the internal audit-log path set at construction, not user-controlled
	if err != nil {
		return fmt.Errorf("audit: open log %s: %w", logPath, err)
	}
	if _, werr := f.Write(line); werr != nil {
		_ = f.Close()
		return fmt.Errorf("audit: write log: %w", werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("audit: sync log: %w", serr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("audit: close log: %w", cerr)
	}
	return nil
}

// sourceMode returns path's permission bits, or 0600 when they cannot be read.
// Used to carry a file's mode into its backup (and back out at restore time)
// so a restore never silently flips a 0644 unit file to 0600 (R2-W3).
func sourceMode(path string) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return 0o600
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
