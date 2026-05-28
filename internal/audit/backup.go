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
	"strings"
	"time"
)

// Backup atomically copies src to <src>.bak.<timestamp> in the same directory.
// It returns the path of the backup file on success.
func Backup(src string) (string, error) {
	content, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("audit: backup read %s: %w", src, err)
	}

	// Nanosecond resolution so repeated writes within the same second do not
	// collide and overwrite an earlier (potentially original) backup. The
	// fixed-width fractional part keeps lexical order chronological.
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dst := fmt.Sprintf("%s.bak.%s", src, stamp)

	if err := os.WriteFile(dst, content, 0o600); err != nil { //nolint:gosec
		return "", fmt.Errorf("audit: backup write %s: %w", dst, err)
	}
	return dst, nil
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

	content, err := os.ReadFile(cleanBak) //nolint:gosec
	if err != nil {
		return fmt.Errorf("audit: restore read backup %s: %w", cleanBak, err)
	}

	tmp := cleanDst + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("audit: restore write tmp %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, cleanDst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: restore rename %s → %s: %w", tmp, cleanDst, err)
	}
	return nil
}
