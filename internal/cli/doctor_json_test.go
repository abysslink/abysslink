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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDoctorFindingJSONNoANSI verifies that buildDoctorFindings converts module
// findings to doctorFinding records that produce ANSI-free JSON via PrintJSON.
func TestDoctorFindingJSONNoANSI(t *testing.T) {
	findings := []modules.Finding{
		{Module: "tailscale", Check: "installed", Severity: modules.SeverityOK, Message: "installed"},
		{Module: "ssh", Check: "checkperiod", Severity: modules.SeverityWarning, Message: "period too long"},
		{Module: "hardening", Check: "filevault", Severity: modules.SeverityFatal, Message: "not enabled"},
	}

	records := buildDoctorFindings(findings)
	require.Len(t, records, 3, "should have 3 records")

	// Verify structure.
	assert.Equal(t, "tailscale", records[0].Module)
	assert.Equal(t, "ok", records[0].Severity)
	assert.Equal(t, "ssh", records[1].Module)
	assert.Equal(t, "warn", records[1].Severity)
	assert.Equal(t, "hardening", records[2].Module)
	assert.Equal(t, "fatal", records[2].Severity)

	// Emit via PrintJSON and verify no ANSI escape bytes.
	var buf bytes.Buffer
	p := NewJSONPrinterTo(&buf, &buf)
	p.PrintJSON(records)

	output := buf.String()
	assert.False(t, strings.Contains(output, "\x1b"),
		"JSON output must contain no ANSI ESC bytes; got: %q", output)

	// Verify it round-trips cleanly.
	var decoded []doctorFinding
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &decoded))
	assert.Len(t, decoded, 3)
}

// TestDoctorFindingSeverityMapping verifies the severity string mapping.
func TestDoctorFindingSeverityMapping(t *testing.T) {
	cases := []struct {
		input modules.Severity
		want  string
	}{
		{modules.SeverityOK, "ok"},
		{modules.SeverityWarning, "warn"},
		{modules.SeverityFatal, "fatal"},
	}
	for _, tc := range cases {
		f := modules.Finding{Severity: tc.input}
		records := buildDoctorFindings([]modules.Finding{f})
		require.Len(t, records, 1)
		assert.Equal(t, tc.want, records[0].Severity)
	}
}

// TestDoctorFindingFixField verifies that the Fix field is populated for known checks.
func TestDoctorFindingFixField(t *testing.T) {
	findings := []modules.Finding{
		{Module: "hardening", Check: "filevault", Severity: modules.SeverityFatal, Message: "not enabled"},
	}
	records := buildDoctorFindings(findings)
	require.Len(t, records, 1)
	assert.NotEmpty(t, records[0].Fix, "Fix should be populated for known check 'filevault'")
}

// TestDoctorSeverityGroupedHuman verifies the count line produced by doctorSeverityCounts.
func TestDoctorSeverityGroupedHuman(t *testing.T) {
	findings := []modules.Finding{
		{Module: "tailscale", Check: "installed", Severity: modules.SeverityOK, Message: ""},
		{Module: "tailscale", Check: "installed", Severity: modules.SeverityOK, Message: ""},
		{Module: "ssh", Check: "checkperiod", Severity: modules.SeverityWarning, Message: ""},
		{Module: "hardening", Check: "filevault", Severity: modules.SeverityFatal, Message: ""},
	}

	line := doctorSeverityCounts(findings)
	assert.Contains(t, line, "ok")
	assert.Contains(t, line, "warn")
	assert.Contains(t, line, "fatal")
}
