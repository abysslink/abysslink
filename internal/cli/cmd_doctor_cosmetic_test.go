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

package cli

import (
	"testing"
)

// TestFindingFix_NbLock asserts that findingFix("nb-lock") exists in the
// findingFix map and returns the empty string — matching the hs-lock
// convention for a permanent advisory where no automated fix is possible
// (Tailnet Lock / TKA is not available on NetBird).
func TestFindingFix_NbLock(t *testing.T) {
	fix := findingFix("nb-lock")
	if fix != "" {
		t.Fatalf("expected findingFix(\"nb-lock\") == \"\", got %q", fix)
	}
}

// TestThreatRows_NtfyVersion asserts that the base threatRows slice contains
// an entry whose failChecks slice includes "ntfy-version" (DOC-04 D-10).
// The ntfy-version floor check is backend-agnostic and belongs in the base
// rows, not in the per-backend backendRows map (RESEARCH.md Assumption A3).
func TestThreatRows_NtfyVersion(t *testing.T) {
	found := false
	for _, row := range threatRows {
		for _, id := range row.failChecks {
			if id == "ntfy-version" {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatal("expected threatRows to contain an entry with failCheck \"ntfy-version\", none found")
	}
}
