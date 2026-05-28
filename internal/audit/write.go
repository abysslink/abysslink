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
func (a *Audit) WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error {
	if dryRun {
		return a.Append("write", path, content, true)
	}

	// Back up an existing file before overwriting it so the change is reversible.
	if _, statErr := os.Stat(path); statErr == nil {
		if _, bErr := Backup(path); bErr != nil {
			return fmt.Errorf("audit: backup before write %s: %w", path, bErr)
		}
	}

	tmp := path + ".abysslink.tmp"
	if err := os.WriteFile(tmp, content, perm); err != nil { //nolint:gosec // perm supplied by caller; tmp is path-derived
		return fmt.Errorf("audit: write temp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: rename %s → %s: %w", tmp, path, err)
	}

	return a.Append("write", path, content, false)
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
