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

package metrics

import (
	"crypto/sha256"
	"fmt"
)

// labelAllowlist is the compile-time set of permitted metric label names
// (OBS-04). Any label name not in this set is mapped to "other" by
// SanitizeLabel, which bounds metric cardinality and prevents high-cardinality
// or sensitive identifiers (hostname, topic, user, node_id, ip, ...) from
// leaking into the metrics surface.
var labelAllowlist = map[string]struct{}{
	"severity": {},
	"check_id": {},
	"backend":  {},
	"result":   {},
	"rig":      {},
}

// IsAllowedLabel reports whether name is in the compile-time label allowlist
// (OBS-04). Callers that need to distinguish "this label name is forbidden"
// from "SanitizeLabel returned its catch-all sentinel" must use this predicate
// rather than comparing SanitizeLabel's output to "other" — the latter couples
// to an implementation detail and would misfire if a future allowlist entry
// were literally named "other" (WR-04).
func IsAllowedLabel(name string) bool {
	_, ok := labelAllowlist[name]
	return ok
}

// SanitizeLabel returns name unchanged when it is in the compile-time
// allowlist, otherwise it returns "other". This collapses unknown label names
// to a single bounded key so metric cardinality cannot be inflated by callers
// (OBS-04, T-18-02).
func SanitizeLabel(name string) string {
	if IsAllowedLabel(name) {
		return name
	}
	return "other"
}

// OpaqueRigLabel returns a deterministic, non-reversible identifier for a rig.
// It hashes rigName with SHA-256 and returns the hex encoding of the first 8
// bytes (16 hex characters). The raw hostname, IP, or node_id is never exposed
// as a label value (OBS-04, T-18-03).
func OpaqueRigLabel(rigName string) string {
	sum := sha256.Sum256([]byte(rigName))
	return fmt.Sprintf("%x", sum[:8])
}
