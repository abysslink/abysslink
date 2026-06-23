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

// withStatedirPresence swaps the injectable statedir-presence probe for the
// duration of a test and restores it afterward.
func withStatedirPresence(t *testing.T, present bool) {
	t.Helper()
	orig := tailscaledStatedirPresent
	tailscaledStatedirPresent = func(context.Context, shell.Runner) bool { return present }
	t.Cleanup(func() { tailscaledStatedirPresent = orig })
}

// ── tailscaleStatedirFinding ─────────────────────────────────────────────────

// TestTailscaleStatedir_LockOnNoStatedir_Fatal: Lock enabled with no statedir is
// a FATAL fail-closed finding (Lock signing checks are not enforced).
func TestTailscaleStatedir_LockOnNoStatedir_Fatal(t *testing.T) {
	withStatedirPresence(t, false)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`, ExitCode: 0}},
	)
	f := tailscaleStatedirFinding(context.Background(), runner)
	assert.Equal(t, "tailscale-statedir", f.Check)
	assert.Equal(t, modules.SeverityFatal, f.Severity, "Lock on + no statedir must be FATAL")
}

// TestTailscaleStatedir_LockOnWithStatedir_OK: Lock enabled but a statedir is
// present → OK (Lock state persists, signing checks enforced).
func TestTailscaleStatedir_LockOnWithStatedir_OK(t *testing.T) {
	withStatedirPresence(t, true)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`, ExitCode: 0}},
	)
	f := tailscaleStatedirFinding(context.Background(), runner)
	assert.Equal(t, modules.SeverityOK, f.Severity, "Lock on + statedir present must be OK")
}

// TestTailscaleStatedir_LockOff_OK: Lock disabled → no false FATAL even when no
// statedir is present (the statedir only matters while Lock is on).
func TestTailscaleStatedir_LockOff_OK(t *testing.T) {
	withStatedirPresence(t, false)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: `{"Enabled":false}`, ExitCode: 0}},
	)
	f := tailscaleStatedirFinding(context.Background(), runner)
	assert.Equal(t, modules.SeverityOK, f.Severity, "Lock off must not produce a false FATAL")
}

// TestTailscaleStatedir_ProbeFail_Warn: an unprobeable lock status (exec error
// or non-zero exit) degrades to WARN, never a silent OK (fail-honest).
func TestTailscaleStatedir_ProbeFail_Warn(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{Err: assert.AnError})
	f := tailscaleStatedirFinding(context.Background(), runner)
	assert.Equal(t, modules.SeverityWarning, f.Severity, "unprobeable lock status must WARN (fail-honest)")
}

// TestTailscaleStatedir_NonZeroExit_Warn: a non-zero exit must WARN even though
// ExecRunner normalizes it to (Result, nil).
func TestTailscaleStatedir_NonZeroExit_Warn(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`, ExitCode: 1}},
	)
	f := tailscaleStatedirFinding(context.Background(), runner)
	assert.Equal(t, modules.SeverityWarning, f.Severity, "non-zero lock-status exit must WARN")
}

// ── opensshFloorFindings ─────────────────────────────────────────────────────

// findOpenSSHFinding returns the finding with the given check ID from the slice.
func findOpenSSHFinding(findings []modules.Finding, check string) *modules.Finding {
	for i := range findings {
		if findings[i].Check == check {
			return &findings[i]
		}
	}
	return nil
}

// TestOpenSSHFloor_BelowVersion_Warn: ssh < 10.0 → WARN openssh-version (mosh
// fallback exists — never FATAL per CONTEXT).
func TestOpenSSHFloor_BelowVersion_Warn(t *testing.T) {
	runner := shell.NewMockRunner(
		// ssh -V prints to stderr.
		shell.Call{Result: shell.Result{Stderr: "OpenSSH_9.6p1, LibreSSL 3.3.6\n", ExitCode: 0}},
		// ssh -Q kex includes the PQ-KEX so only the version row is WARN here.
		shell.Call{Result: shell.Result{Stdout: "sntrup761x25519-sha512\nmlkem768x25519-sha256\n", ExitCode: 0}},
	)
	findings := opensshFloorFindings(context.Background(), runner)
	v := findOpenSSHFinding(findings, "openssh-version")
	require.NotNil(t, v, "openssh-version finding must be present")
	assert.Equal(t, modules.SeverityWarning, v.Severity, "OpenSSH 9.6 below 10.0 must WARN, never FATAL")
}

// TestOpenSSHFloor_AtVersion_OK: ssh >= 10.0 → OK openssh-version.
func TestOpenSSHFloor_AtVersion_OK(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stderr: "OpenSSH_10.0p1, LibreSSL 3.3.6\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "mlkem768x25519-sha256\n", ExitCode: 0}},
	)
	findings := opensshFloorFindings(context.Background(), runner)
	v := findOpenSSHFinding(findings, "openssh-version")
	require.NotNil(t, v)
	assert.Equal(t, modules.SeverityOK, v.Severity, "OpenSSH 10.0 meets the floor — OK")
}

// TestOpenSSHPQKex_Missing_Warn: ssh -Q kex lacking mlkem768x25519-sha256 → WARN.
func TestOpenSSHPQKex_Missing_Warn(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stderr: "OpenSSH_10.0p1\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "curve25519-sha256\necdh-sha2-nistp256\n", ExitCode: 0}},
	)
	findings := opensshFloorFindings(context.Background(), runner)
	pq := findOpenSSHFinding(findings, "openssh-pqkex")
	require.NotNil(t, pq, "openssh-pqkex finding must be present")
	assert.Equal(t, modules.SeverityWarning, pq.Severity, "missing mlkem768x25519-sha256 must WARN")
}

// TestOpenSSHPQKex_Present_OK: ssh -Q kex containing mlkem768x25519-sha256 → OK.
func TestOpenSSHPQKex_Present_OK(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stderr: "OpenSSH_10.0p1\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "curve25519-sha256\nmlkem768x25519-sha256\n", ExitCode: 0}},
	)
	findings := opensshFloorFindings(context.Background(), runner)
	pq := findOpenSSHFinding(findings, "openssh-pqkex")
	require.NotNil(t, pq)
	assert.Equal(t, modules.SeverityOK, pq.Severity, "present mlkem768x25519-sha256 — OK")
}

// TestOpenSSHFloor_ProbeFail_Warn: both probes failing → both WARN, never silent OK.
func TestOpenSSHFloor_ProbeFail_Warn(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Err: assert.AnError}, // ssh -V absent
		shell.Call{Err: assert.AnError}, // ssh -Q kex absent
	)
	findings := opensshFloorFindings(context.Background(), runner)
	v := findOpenSSHFinding(findings, "openssh-version")
	pq := findOpenSSHFinding(findings, "openssh-pqkex")
	require.NotNil(t, v)
	require.NotNil(t, pq)
	assert.Equal(t, modules.SeverityWarning, v.Severity, "unprobeable ssh -V must WARN")
	assert.Equal(t, modules.SeverityWarning, pq.Severity, "unprobeable ssh -Q kex must WARN")
}

// TestDoctorFloors_FixEntries: findingFix has remediation text for the three new
// bespoke check IDs.
func TestDoctorFloors_FixEntries(t *testing.T) {
	for _, check := range []string{"tailscale-statedir", "openssh-version", "openssh-pqkex"} {
		assert.NotEmpty(t, findingFix(check), "findingFix must have a remediation entry for %q", check)
	}
}
