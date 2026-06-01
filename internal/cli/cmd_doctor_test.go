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

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
)

// ── TestDoctorFleetFixStrings ─────────────────────────────────────────────────

// TestDoctorFleetFixStrings verifies that findingFix returns a non-empty
// remediation string for each of the three mr-* fleet doctor checks.
func TestDoctorFleetFixStrings(t *testing.T) {
	cases := []string{
		"mr-rig-isolation",
		"mr-topic-isolation",
		"mr-key-uniqueness",
	}
	for _, check := range cases {
		fix := findingFix(check)
		assert.NotEmpty(t, fix, "findingFix(%q) must return a non-empty remediation string", check)
	}
}

// ── TestRemoteSeverity ────────────────────────────────────────────────────────

// TestRemoteSeverity verifies the remoteSeverity converter maps JSON strings to
// modules.Severity integers correctly, including graceful degradation on unknown values.
// WR-05: assertions now compare against expected Severity constants, not against the
// function's own output — the old form (remoteSeverity(x) == remoteSeverity(x)) was
// tautological and would pass even if the function returned wrong values for every input.
func TestRemoteSeverity(t *testing.T) {
	assert.Equal(t, modules.SeverityOK, remoteSeverity("ok"), `"ok" must map to SeverityOK`)
	assert.Equal(t, modules.SeverityFatal, remoteSeverity("fatal"), `"fatal" must map to SeverityFatal`)
	assert.Equal(t, modules.SeverityWarning, remoteSeverity("warn"), `"warn" must map to SeverityWarning`)
	// Unknown values must degrade to Warning — not crash, not OK.
	assert.Equal(t, modules.SeverityWarning, remoteSeverity("unknown-severity"), "unknown string must degrade to SeverityWarning")
	assert.Equal(t, modules.SeverityWarning, remoteSeverity(""), "empty string must degrade to SeverityWarning")
}
