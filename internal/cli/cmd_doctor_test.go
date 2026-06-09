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

// ── CLI-06: doctor exit-code parity between JSON and human output ────────────

// TestFindingsSeverityFlags verifies the shared severity predicate that both
// the JSON and human doctor paths use to derive the exit code (CLI-06).
func TestFindingsSeverityFlags(t *testing.T) {
	cases := []struct {
		name      string
		findings  []modules.Finding
		wantFatal bool
		wantWarn  bool
	}{
		{"empty", nil, false, false},
		{"all-ok", []modules.Finding{{Severity: modules.SeverityOK}}, false, false},
		{"warn-only", []modules.Finding{{Severity: modules.SeverityOK}, {Severity: modules.SeverityWarning}}, false, true},
		{"fatal-only", []modules.Finding{{Severity: modules.SeverityFatal}}, true, false},
		{"fatal-and-warn", []modules.Finding{{Severity: modules.SeverityWarning}, {Severity: modules.SeverityFatal}}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hasFatal, hasWarn := findingsSeverityFlags(tc.findings)
			assert.Equal(t, tc.wantFatal, hasFatal, "hasFatal")
			assert.Equal(t, tc.wantWarn, hasWarn, "hasWarn")
		})
	}
}

// TestDoctorExitErr verifies the single exit decision shared by the doctor
// JSON and human paths: fatal→2, warn→1, clean→nil (CLI-06). Before this fix
// the JSON branch always returned nil/exit 0 even with FATAL findings.
func TestDoctorExitErr(t *testing.T) {
	// Fatal wins: exit 2.
	err := doctorExitErr(true, true)
	var ee *exitError
	if assert.ErrorAs(t, err, &ee, "fatal must map to an exitError") {
		assert.Equal(t, exitCodeFatal, ee.ExitCode(), "fatal findings must exit 2")
	}

	// Warn only: exit 1.
	err = doctorExitErr(false, true)
	ee = nil
	if assert.ErrorAs(t, err, &ee, "warn must map to an exitError") {
		assert.Equal(t, exitCodeError, ee.ExitCode(), "warning findings must exit 1")
	}

	// Clean: nil (exit 0).
	assert.NoError(t, doctorExitErr(false, false), "no findings must exit 0")
}
