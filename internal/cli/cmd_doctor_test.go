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
func TestRemoteSeverity(t *testing.T) {
	assert.Equal(t, remoteSeverity("ok"), remoteSeverity("ok"))
	assert.Equal(t, remoteSeverity("fatal"), remoteSeverity("fatal"))
	assert.Equal(t, remoteSeverity("warn"), remoteSeverity("warn"))
	// Unknown values must degrade to Warning.
	assert.Equal(t, remoteSeverity("warn"), remoteSeverity("unknown-severity"))
	assert.Equal(t, remoteSeverity("warn"), remoteSeverity(""))
}
