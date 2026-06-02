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
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportExitCode0(t *testing.T) {
	findings := []modules.Finding{
		{Module: "tailscale", Check: "installed", Severity: modules.SeverityOK},
		{Module: "ssh", Check: "checkperiod", Severity: modules.SeverityOK},
	}
	assert.Equal(t, exitCodeOK, reportExitCode(findings))
}

func TestReportExitCode1(t *testing.T) {
	findings := []modules.Finding{
		{Module: "tailscale", Check: "installed", Severity: modules.SeverityOK},
		{Module: "ssh", Check: "checkperiod", Severity: modules.SeverityWarning},
	}
	assert.Equal(t, exitCodeError, reportExitCode(findings))
}

func TestReportExitCode2(t *testing.T) {
	findings := []modules.Finding{
		{Module: "ssh", Check: "checkperiod", Severity: modules.SeverityWarning},
		{Module: "hardening", Check: "filevault", Severity: modules.SeverityFatal},
	}
	assert.Equal(t, exitCodeFatal, reportExitCode(findings))
}

func TestReportAuditEntries(t *testing.T) {
	// 25 entries; default tail=20 returns the last 20, tail=5 returns the last 5.
	entries := make([]audit.Entry, 25)
	for i := range entries {
		entries[i] = audit.Entry{Op: "write", Target: "f", Time: time.Now()}
	}
	assert.Len(t, tailEntrySlice(entries, 20), 20)
	assert.Len(t, tailEntrySlice(entries, 5), 5)
	// tail larger than slice returns all.
	assert.Len(t, tailEntrySlice(entries, 100), 25)
	// the last 5 are the final 5 of the input.
	last5 := tailEntrySlice(entries, 5)
	assert.Equal(t, entries[24], last5[4])
}

func TestReportJSON(t *testing.T) {
	out := reportOutput{
		Findings: []doctorFinding{
			{Module: "ssh", Check: "checkperiod", Severity: "warn", Message: "period too long"},
		},
		AuditEntries: []audit.Entry{{Op: "write", Target: "f"}},
		RigResults:   []rigReachability{{RigID: "abc123", Reachable: true}},
	}

	var buf bytes.Buffer
	p := NewJSONPrinterTo(&buf, &buf)
	p.PrintJSON(out)

	output := buf.String()
	assert.False(t, strings.Contains(output, "\x1b"), "JSON must be ANSI-free; got %q", output)

	var decoded reportOutput
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &decoded))
	assert.Len(t, decoded.Findings, 1)
	assert.Len(t, decoded.RigResults, 1)
	assert.Equal(t, "abc123", decoded.RigResults[0].RigID)
}

func TestReportRigReachabilityOpaque(t *testing.T) {
	// rigReachability must carry only the opaque rig id — never a raw hostname.
	rr := newRigReachability("my-secret-rig-hostname", true)
	b, err := json.Marshal(rr)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "my-secret-rig-hostname")
}

func TestNewReportCmdRegistered(t *testing.T) {
	cmd := newReportCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "report", cmd.Name())
	tail, err := cmd.Flags().GetInt("tail")
	require.NoError(t, err)
	assert.Equal(t, 20, tail)
}
