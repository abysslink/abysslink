//go:build linux || darwin

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
	"fmt"

	"golang.org/x/sys/unix"
)

// WithAppendLock runs fn while holding the SAME cross-process advisory flock
// that WriteFile / Append take — the exclusive lock on the sibling
// "<logPath>.lock" file. It lets a caller perform a multi-step
// read-modify-write (reload-from-disk, mutate, write) that is atomic with
// respect to any other process's audit-backed write to files governed by the
// same audit log.
//
// CAUTION: the flock is NOT re-entrant (each acquisition opens a fresh fd and
// LOCK_EX blocks on a second hold from the same process). fn therefore MUST NOT
// call any audit method that re-acquires the lock — WriteFile, Append, etc. all
// do. Use the *Locked write paths (e.g. *Audit.UpdateLocked is invoked for you
// by Update) inside fn, or write the file directly. The intended pattern is to
// go through Update, which acquires this lock, calls back for the fresh content,
// then records the audit entry and writes — all under the single held lock.
//
// ctx is honoured before the (potentially blocking) lock acquisition; once the
// lock is held fn runs to completion and the lock is always released.
func WithAppendLock(ctx context.Context, logPath string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lockFD, err := acquireAuditLock(logPath)
	if err != nil {
		return fmt.Errorf("audit: acquire process lock: %w", err)
	}
	defer releaseAuditLock(lockFD)
	return fn()
}

// acquireAuditLock opens (or creates) a sibling .lock file beside logPath and
// acquires an exclusive OS advisory flock on it. The caller MUST call
// releaseAuditLock(fd) when done — even on error paths — to release the fd.
// The log file itself is NOT locked; a sibling avoids fd-ordering ambiguity
// with the O_APPEND write fd (RESEARCH.md RQ-1).
// Note: callers are wired in plan 25-04 (AUD-02); nolint until that plan runs.
func acquireAuditLock(logPath string) (int, error) { //nolint:unused // wired by plan 25-04 (AUD-02)
	lockPath := logPath + ".lock"
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		return -1, fmt.Errorf("open lock file %s: %w", lockPath, err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("flock %s: %w", lockPath, err)
	}
	return fd, nil
}

// releaseAuditLock releases the exclusive flock and closes the lock file fd
// acquired by acquireAuditLock. Return values from both unix calls are
// intentionally discarded — failure to unlock is non-actionable at this layer
// (the OS releases all flocks on process exit regardless).
func releaseAuditLock(fd int) { //nolint:unused // wired by plan 25-04 (AUD-02)
	_ = unix.Flock(fd, unix.LOCK_UN)
	_ = unix.Close(fd)
}
