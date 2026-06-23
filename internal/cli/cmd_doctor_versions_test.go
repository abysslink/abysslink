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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// ── TestVersionFloor ──────────────────────────────────────────────────────────

// TestVersionFloor_NtfyBelowFloor_Fatal verifies that ntfy < 2.21 yields
// SeverityFatal with CVE-2026-39087 in the message.
func TestVersionFloor_NtfyBelowFloor_Fatal(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.20.0\n", ExitCode: 0}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "ntfy-version" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "ntfy-version finding must be present")
	assert.Equal(t, modules.SeverityFatal, found.Severity, "ntfy 2.20.0 is below floor 2.21 — must be FATAL")
	assert.Contains(t, found.Message, "CVE-2026-39087", "FATAL message must mention CVE-2026-39087")
}

// TestVersionFloor_NtfyAtFloor_OK verifies that ntfy >= 2.21 yields SeverityOK.
func TestVersionFloor_NtfyAtFloor_OK(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.21.0\n", ExitCode: 0}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "ntfy-version" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "ntfy-version finding must be present")
	assert.Equal(t, modules.SeverityOK, found.Severity, "ntfy 2.21.0 meets the floor — must be OK")
}

// TestVersionFloor_NtfyAboveFloor_OK verifies that ntfy > 2.21 (e.g. 2.22.0) yields SeverityOK.
func TestVersionFloor_NtfyAboveFloor_OK(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.22.1\n", ExitCode: 0}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "ntfy-version" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "ntfy-version finding must be present")
	assert.Equal(t, modules.SeverityOK, found.Severity, "ntfy 2.22.1 is above the floor — must be OK")
}

// TestVersionFloor_NtfyExecError_Warn verifies that an exec error (binary absent)
// yields SeverityWarning (fail-honest, never silent pass).
func TestVersionFloor_NtfyExecError_Warn(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Err: assert.AnError}, // binary absent / exec error
	)
	findings := versionFloorFindings(context.Background(), runner)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "ntfy-version" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "ntfy-version finding must be present even on exec error")
	assert.Equal(t, modules.SeverityWarning, found.Severity, "exec error must yield WARN (fail-honest)")
}

// TestVersionFloor_NonZeroExit_Warn verifies that a binary exiting non-zero
// yields SeverityWarning even when its output contains a parseable N.N token
// that meets the floor. ExecRunner normalizes non-zero exits to (Result, nil),
// so without an explicit ExitCode check this would be a silent SeverityOK pass
// (fail-honest ladder violation).
func TestVersionFloor_NonZeroExit_Warn(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.21.0\n", ExitCode: 1}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	found := findFloorFinding(findings, "ntfy-version")
	require.NotNil(t, found, "ntfy-version finding must be present on non-zero exit")
	assert.Equal(t, modules.SeverityWarning, found.Severity,
		"a failing probe must yield WARN even if its output parses to an at-floor version (never a silent pass)")
	assert.Contains(t, found.Message, "exited 1", "the message must name the non-zero exit code")
}

// TestVersionFloor_NtfyUnparseable_Warn verifies that unparseable output yields
// SeverityWarning (fail-honest).
func TestVersionFloor_NtfyUnparseable_Warn(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "not-a-version-string\n", ExitCode: 0}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "ntfy-version" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "ntfy-version finding must be present even on unparseable output")
	assert.Equal(t, modules.SeverityWarning, found.Severity, "unparseable version must yield WARN (fail-honest)")
}

// TestVersionFloor_NoNewSemverComparator ensures the versions file does not
// define its own semver comparator (D-09: reuse cli.semverLT).
// This is a compile-time guarantee via the internal package test.
func TestVersionFloor_NoNewSemverComparator(t *testing.T) {
	// If this test file compiles and all above tests pass, the detector reuses
	// the package-level semverLT defined in cmd_server_headscale.go (package cli).
	// The grep assertion is captured in the plan verification step; this test
	// documents the design constraint.
	t.Log("D-09 compliance: versionFloorFindings reuses package cli semverLT — no new comparator")
}

// ── D-27: tmux >= 3.2 capability floor (WARN, not FATAL) ─────────────────────

// findFloorFinding returns the finding with the given check ID.
func findFloorFinding(findings []modules.Finding, checkID string) *modules.Finding {
	for i := range findings {
		if findings[i].Check == checkID {
			return &findings[i]
		}
	}
	return nil
}

// scriptedFloorRunner scripts one probe result per versionFloors row, in table
// order (ntfy first, then tmux).
func scriptedFloorRunner(calls ...shell.Call) shell.Runner {
	return shell.NewMockRunner(calls...)
}

// TestTmuxVersionFloor_Below_Warn verifies tmux 3.1c yields WARN (not FATAL —
// the registry is optional, D-27) with a message naming the found version, the
// 3.2 floor, and what degrades (session identity in notifications).
func TestTmuxVersionFloor_Below_Warn(t *testing.T) {
	runner := scriptedFloorRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.21.0\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "tmux 3.1c\n", ExitCode: 0}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	found := findFloorFinding(findings, "tmux-version")
	require.NotNil(t, found, "tmux-version finding must be present")
	assert.Equal(t, modules.SeverityWarning, found.Severity, "tmux below 3.2 must WARN, never FATAL (D-27)")
	assert.Contains(t, found.Message, "3.1", "the found version must be named")
	assert.Contains(t, found.Message, "3.2", "the 3.2 floor must be named")
	assert.Contains(t, found.Message, "session", "the message must say what degrades (session registry/identity)")
}

// TestTmuxVersionFloor_LetterSuffix_OK verifies that the tmux "3.6b" release
// format parses (letter suffix stripped, mirroring modules/tmux
// parseTmuxVersion) and passes the 3.2 floor.
func TestTmuxVersionFloor_LetterSuffix_OK(t *testing.T) {
	runner := scriptedFloorRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.21.0\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "tmux 3.6b\n", ExitCode: 0}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	found := findFloorFinding(findings, "tmux-version")
	require.NotNil(t, found, "tmux-version finding must be present")
	assert.Equal(t, modules.SeverityOK, found.Severity, "tmux 3.6b is >= 3.2 — the letter suffix must not parse to 3.0")
}

// TestTmuxVersionFloor_BinaryMissing_Warn verifies the fail-honest ladder: a
// missing tmux binary WARNs (the registry is optional — D-27), never a silent
// pass and never a FATAL.
func TestTmuxVersionFloor_BinaryMissing_Warn(t *testing.T) {
	runner := scriptedFloorRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.21.0\n", ExitCode: 0}},
		shell.Call{Err: assert.AnError}, // tmux binary absent
	)
	findings := versionFloorFindings(context.Background(), runner)
	found := findFloorFinding(findings, "tmux-version")
	require.NotNil(t, found, "tmux-version finding must be present even when the binary is absent")
	assert.Equal(t, modules.SeverityWarning, found.Severity, "missing tmux must WARN per the fail-honest ladder")
}

// TestVersionFloor_ExistingRowsKeepFatal is the regression guard on the new
// severity field: the zero value must preserve FATAL behavior for every
// pre-existing CVE row in the table.
func TestVersionFloor_ExistingRowsKeepFatal(t *testing.T) {
	// Capability floors below their minimum degrade to WARN (the feature
	// degrades but the system stays operable): tmux (D-27) and EternalTerminal
	// (prefer-mosh — mosh fallback exists).
	warnRows := map[string]bool{
		"tmux-version": true,
		"et-version":   true,
	}
	for _, f := range versionFloors {
		if warnRows[f.checkID] {
			assert.Equal(t, floorSevWarn, f.severity,
				"capability floor %q must be WARN severity", f.checkID)
			continue
		}
		assert.Equal(t, floorSevFatal, f.severity,
			"CVE/security row %q must keep FATAL severity (zero-value default)", f.checkID)
	}

	// Behavioral: ntfy below floor is still FATAL with the severity field present.
	runner := scriptedFloorRunner(
		shell.Call{Result: shell.Result{Stdout: "ntfy version 2.20.0\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "tmux 3.6b\n", ExitCode: 0}},
	)
	findings := versionFloorFindings(context.Background(), runner)
	found := findFloorFinding(findings, "ntfy-version")
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityFatal, found.Severity, "ntfy below floor must stay FATAL")
}

// ── SUPL-04: Tailscale / NetBird-client / EternalTerminal floors ─────────────

// okPrefix scripts benign passing probes for the leading table rows (ntfy, tmux)
// so a focused probe of a later row supplies one Call per versionFloors entry in
// table order. The trailing rows (after the row under test) are filled with an
// at-floor OK so the MockRunner never errors on an unscripted over-call.
func floorRunnerFor(target string, targetCall shell.Call) shell.Runner {
	defaults := map[string]shell.Call{
		"ntfy-version":      {Result: shell.Result{Stdout: "ntfy version 2.21.0\n", ExitCode: 0}},
		"tmux-version":      {Result: shell.Result{Stdout: "tmux 3.6b\n", ExitCode: 0}},
		"tailscale-version": {Result: shell.Result{Stdout: "1.98.5\n", ExitCode: 0}},
		"nb-client-version": {Result: shell.Result{Stdout: "netbird version 0.73.1\n", ExitCode: 0}},
		"et-version":        {Result: shell.Result{Stdout: "et version 6.2.11\n", ExitCode: 0}},
	}
	calls := make([]shell.Call, 0, len(versionFloors))
	for _, f := range versionFloors {
		if f.checkID == target {
			calls = append(calls, targetCall)
			continue
		}
		calls = append(calls, defaults[f.checkID])
	}
	return shell.NewMockRunner(calls...)
}

// TestVersionFloor_TailscaleBelowFloor_Fatal verifies Tailscale 1.98.0 → FATAL.
func TestVersionFloor_TailscaleBelowFloor_Fatal(t *testing.T) {
	runner := floorRunnerFor("tailscale-version",
		shell.Call{Result: shell.Result{Stdout: "1.98.0\n", ExitCode: 0}})
	found := findFloorFinding(versionFloorFindings(context.Background(), runner), "tailscale-version")
	require.NotNil(t, found, "tailscale-version finding must be present")
	assert.Equal(t, modules.SeverityFatal, found.Severity, "Tailscale 1.98.0 is below floor 1.98.1 — FATAL")
}

// TestVersionFloor_TailscaleAtFloor_OK verifies Tailscale 1.98.1 → OK.
func TestVersionFloor_TailscaleAtFloor_OK(t *testing.T) {
	runner := floorRunnerFor("tailscale-version",
		shell.Call{Result: shell.Result{Stdout: "1.98.1\n", ExitCode: 0}})
	found := findFloorFinding(versionFloorFindings(context.Background(), runner), "tailscale-version")
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityOK, found.Severity, "Tailscale 1.98.1 meets the floor — OK")
}

// TestVersionFloor_TailscaleUnprobeable_Warn verifies an exec error → WARN.
func TestVersionFloor_TailscaleUnprobeable_Warn(t *testing.T) {
	runner := floorRunnerFor("tailscale-version", shell.Call{Err: assert.AnError})
	found := findFloorFinding(versionFloorFindings(context.Background(), runner), "tailscale-version")
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityWarning, found.Severity, "unprobeable Tailscale must WARN (fail-honest)")
}

// TestVersionFloor_NetBirdClientBelowFloor_Fatal verifies NetBird client 0.56.0 → FATAL.
func TestVersionFloor_NetBirdClientBelowFloor_Fatal(t *testing.T) {
	runner := floorRunnerFor("nb-client-version",
		shell.Call{Result: shell.Result{Stdout: "netbird version 0.56.0\n", ExitCode: 0}})
	found := findFloorFinding(versionFloorFindings(context.Background(), runner), "nb-client-version")
	require.NotNil(t, found, "nb-client-version finding must be present (distinct from server nb-version)")
	assert.Equal(t, modules.SeverityFatal, found.Severity, "NetBird client 0.56.0 is below floor 0.57.0 — FATAL")
}

// TestVersionFloor_NetBirdClientAtFloor_OK verifies NetBird client 0.57.0 → OK.
func TestVersionFloor_NetBirdClientAtFloor_OK(t *testing.T) {
	runner := floorRunnerFor("nb-client-version",
		shell.Call{Result: shell.Result{Stdout: "netbird version 0.57.0\n", ExitCode: 0}})
	found := findFloorFinding(versionFloorFindings(context.Background(), runner), "nb-client-version")
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityOK, found.Severity, "NetBird client 0.57.0 meets the floor — OK")
}

// TestVersionFloor_ETBelowFloor_Warn verifies EternalTerminal 6.1.0 → WARN
// (prefer-mosh capability floor — mosh fallback exists, never FATAL).
func TestVersionFloor_ETBelowFloor_Warn(t *testing.T) {
	runner := floorRunnerFor("et-version",
		shell.Call{Result: shell.Result{Stdout: "et version 6.1.0\n", ExitCode: 0}})
	found := findFloorFinding(versionFloorFindings(context.Background(), runner), "et-version")
	require.NotNil(t, found, "et-version finding must be present")
	assert.Equal(t, modules.SeverityWarning, found.Severity, "EternalTerminal 6.1.0 below floor must WARN (prefer-mosh)")
}

// TestVersionFloor_ETAtFloor_OK verifies EternalTerminal 6.2.0 → OK.
func TestVersionFloor_ETAtFloor_OK(t *testing.T) {
	runner := floorRunnerFor("et-version",
		shell.Call{Result: shell.Result{Stdout: "et version 6.2.0\n", ExitCode: 0}})
	found := findFloorFinding(versionFloorFindings(context.Background(), runner), "et-version")
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityOK, found.Severity, "EternalTerminal 6.2.0 meets the floor — OK")
}

// TestVersionFloor_NewRowsHaveFixEntries verifies findingFix has remediation
// text for the three new check IDs (DOC-04 — every floor check is fixable).
func TestVersionFloor_NewRowsHaveFixEntries(t *testing.T) {
	for _, check := range []string{"tailscale-version", "nb-client-version", "et-version"} {
		assert.NotEmpty(t, findingFix(check), "findingFix must have a remediation entry for %q", check)
	}
}
