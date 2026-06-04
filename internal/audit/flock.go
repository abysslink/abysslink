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
	"fmt"

	"golang.org/x/sys/unix"
)

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
