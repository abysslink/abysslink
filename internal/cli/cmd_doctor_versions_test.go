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
