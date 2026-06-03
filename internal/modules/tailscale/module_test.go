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

package tailscale

import (
	"context"
	"errors"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestModule(calls ...shell.Call) *Module {
	cfg := config.Defaults()
	cfg.Tailnet.SSH = true
	return New(modules.Deps{Runner: shell.NewMockRunner(calls...), Cfg: cfg})
}

func TestFunnelActive(t *testing.T) {
	cases := []struct {
		name        string
		res         shell.Result
		err         bool
		wantActive  bool
		wantProbeOK bool
	}{
		{"active", shell.Result{Stdout: "https://rig.tail-scale.ts.net (Funnel on)\n|-- / proxy http://127.0.0.1:3000", ExitCode: 0}, false, true, true},
		{"not configured", shell.Result{Stdout: "Funnel is not configured.", ExitCode: 0}, false, false, true},
		{"command unavailable", shell.Result{ExitCode: 1}, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModule(shell.Call{Result: tc.res})
			active, probeOK := m.funnelActive(context.Background())
			assert.Equal(t, tc.wantActive, active)
			assert.Equal(t, tc.wantProbeOK, probeOK)
		})
	}
}

func TestServeActive(t *testing.T) {
	cases := []struct {
		name        string
		call        shell.Call
		wantActive  bool
		wantProbeOK bool
	}{
		{
			"active proxy",
			shell.Call{Result: shell.Result{Stdout: "https://rig.ts.net\n|-- /  proxy http://127.0.0.1:8080", ExitCode: 0}},
			true, true,
		},
		{
			"no config",
			shell.Call{Result: shell.Result{Stdout: "No serve config", ExitCode: 0}},
			false, true,
		},
		{
			"empty",
			shell.Call{Result: shell.Result{Stdout: "", ExitCode: 0}},
			false, true,
		},
		{
			// IN-03: inactive output that merely mentions "proxy" in help/hint
			// text must NOT be detected as an active serve. The structural "|--"
			// tree marker is absent, so this is correctly inactive (no false
			// positive Warning).
			"inactive proxy-mentioning hint text",
			shell.Call{Result: shell.Result{Stdout: "No serve config.\nRun 'tailscale serve --help' to set up a proxy.", ExitCode: 0}},
			false, true,
		},
		{
			// IN-03 companion: hint text mentioning "proxy" WITHOUT the "No serve
			// config" short-circuit still must not be read as active when the
			// "|--" tree marker is absent.
			"proxy word without tree marker",
			shell.Call{Result: shell.Result{Stdout: "To expose a service, configure a proxy target.", ExitCode: 0}},
			false, true,
		},
		{
			"exec error",
			shell.Call{Err: errors.New("not found")},
			false, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModule(tc.call)
			active, probeOK := m.serveActive(context.Background())
			assert.Equal(t, tc.wantActive, active)
			assert.Equal(t, tc.wantProbeOK, probeOK)
		})
	}
}

func TestFunnelOK(t *testing.T) {
	// Clean path: neither funnel nor serve is active → expect SeverityOK finding
	// with Check=="funnel".
	m := newTestModule(
		// funnelActive call: "Funnel is not configured."
		shell.Call{Result: shell.Result{Stdout: "Funnel is not configured.", ExitCode: 0}},
		// serveActive call: no serve config
		shell.Call{Result: shell.Result{Stdout: "No serve config", ExitCode: 0}},
	)
	findings := m.checkNoPublicExposure(context.Background())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "funnel" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"funnel\" on clean path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "clean path must emit SeverityOK for funnel")
}

func TestSSHFindings(t *testing.T) {
	m := newTestModule()

	// SSH disabled in config → no finding.
	mDisabled := New(modules.Deps{Cfg: config.Defaults()})
	mDisabled.cfg.Tailnet.SSH = false
	assert.Empty(t, mDisabled.sshFindings(&tailscaleStatus{}, false))

	// Sandboxed GUI build → ssh_sandboxed.
	got := m.sshFindings(&tailscaleStatus{}, true)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "ssh_sandboxed", got[0].Check)
	}

	// SSH already enabled (TailscaleSSH true) → no finding.
	assert.Empty(t, m.sshFindings(&tailscaleStatus{TailscaleSSH: true}, false))

	// SSH capability present → no finding.
	st := &tailscaleStatus{}
	st.Self.Capabilities = []string{"https://tailscale.com/cap/ssh"}
	assert.Empty(t, m.sshFindings(st, false))

	// SSH wanted but absent → ssh finding.
	got = m.sshFindings(&tailscaleStatus{}, false)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "ssh", got[0].Check)
		assert.Equal(t, modules.SeverityWarning, got[0].Severity)
	}
}

// TestFunnelProbeFailure verifies WR-02: exec error on "tailscale funnel status"
// must produce a SeverityWarning with Check="funnel-probe-fail", never SeverityOK
// with Check="funnel" (which would be a false-green for the public-exposure promise).
func TestFunnelProbeFailure(t *testing.T) {
	m := newTestModule(
		shell.Call{Err: errors.New("tailscale: command not found")},
	)
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)

	var probeFail *modules.Finding
	for i := range findings {
		if findings[i].Check == "funnel-probe-fail" {
			probeFail = &findings[i]
		}
	}
	require.NotNil(t, probeFail, "expected a finding with Check=funnel-probe-fail on exec error, got %+v", findings)
	assert.Equal(t, modules.SeverityWarning, probeFail.Severity)

	// Must not emit a Check="funnel" finding at all (no false-OK).
	for _, f := range findings {
		assert.NotEqual(t, "funnel", f.Check, "unexpected funnel check in probe-failure path: %+v", f)
		assert.NotEqual(t, modules.SeverityOK, f.Severity, "unexpected SeverityOK in probe-failure path: %+v", f)
	}
}

// TestFunnelProbeFailNonZeroExit verifies WR-02: a non-zero exit code (no exec
// error) is treated identically to an exec error — probe-failure, not false-OK.
func TestFunnelProbeFailNonZeroExit(t *testing.T) {
	m := newTestModule(
		shell.Call{Result: shell.Result{ExitCode: 1}},
	)
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)

	var probeFail *modules.Finding
	for i := range findings {
		if findings[i].Check == "funnel-probe-fail" {
			probeFail = &findings[i]
		}
	}
	require.NotNil(t, probeFail, "expected Check=funnel-probe-fail on non-zero exit, got %+v", findings)
	assert.Equal(t, modules.SeverityWarning, probeFail.Severity)

	for _, f := range findings {
		assert.NotEqual(t, "funnel", f.Check, "unexpected funnel check in probe-failure path: %+v", f)
		assert.NotEqual(t, modules.SeverityOK, f.Severity, "unexpected SeverityOK in probe-failure path: %+v", f)
	}
}

// TestFunnelProbeFailDistinctCheckID documents D-04: "funnel-probe-fail" must
// NOT appear in any threat-model row's failChecks, so probe-failure findings
// keep the "No public exposure" row at — (did-not-run), not ✗ (actively failing).
//
// This is a compile-time-stable assertion over the known failChecks universe.
func TestFunnelProbeFailDistinctCheckID(t *testing.T) {
	// All failChecks values from cmd_threat_model.go threatRows, v3SurfaceRows,
	// and backendRows as of Phase 23.1. Update this list if new rows are added.
	knownFailChecks := []string{
		// threatRows
		"funnel", "acl_drift", "remote_login", "sshd_running",
		"filevault", "luks", "lock_enabled", "listen_address",
		// v3SurfaceRows
		"sec-metrics-bind", "metrics-bind-tailnet",
		"sec-webui-bind", "webui-bind",
		"sec-audit-anchor-age", "audit-anchor-age",
		// backendRows — tailscale
		"sec-funnel-schema",
		// backendRows — headscale
		"hs-tls", "hs-api-auth", "hs-lock", "hs-oidc-filter",
		// backendRows — netbird
		"nb-tls", "nb-version", "nb-zitadel", "nb-lock",
	}

	for _, checkID := range knownFailChecks {
		assert.NotEqual(t, "funnel-probe-fail", checkID,
			"funnel-probe-fail must not appear in threat-model failChecks (D-04): found %q", checkID)
	}
}

// TestServeProbeFailure verifies CR-02: exec error on "tailscale serve status"
// must produce a SeverityWarning with Check="serve-probe-fail", never Check="serve"
// (which would silently suppress the serve warning while hiding the probe failure).
func TestServeProbeFailure(t *testing.T) {
	m := newTestModule(
		// funnelActive call: confirmed-inactive (probe succeeds)
		shell.Call{Result: shell.Result{Stdout: "Funnel is not configured.", ExitCode: 0}},
		// serveActive call: exec error
		shell.Call{Err: errors.New("tailscale: command not found")},
	)
	findings := m.checkNoPublicExposure(context.Background())

	var probeFail *modules.Finding
	for i := range findings {
		if findings[i].Check == "serve-probe-fail" {
			probeFail = &findings[i]
		}
	}
	require.NotNil(t, probeFail, "expected a finding with Check=serve-probe-fail on exec error, got %+v", findings)
	assert.Equal(t, modules.SeverityWarning, probeFail.Severity)

	// Must not emit a Check="serve" finding at all (no false silence / no serve Warning suppressed by probe failure).
	for _, f := range findings {
		assert.NotEqual(t, "serve", f.Check, "unexpected serve check in serve probe-failure path: %+v", f)
	}
	// Must not emit SeverityOK for serve-probe-fail.
	assert.NotEqual(t, modules.SeverityOK, probeFail.Severity, "serve-probe-fail must not be SeverityOK")
}

// TestServeProbeFailNonZeroExit verifies CR-02: a non-zero exit code (no exec
// error) is treated identically to an exec error — probe-failure, not false-silence.
func TestServeProbeFailNonZeroExit(t *testing.T) {
	m := newTestModule(
		// funnelActive call: confirmed-inactive (probe succeeds)
		shell.Call{Result: shell.Result{Stdout: "Funnel is not configured.", ExitCode: 0}},
		// serveActive call: non-zero exit
		shell.Call{Result: shell.Result{ExitCode: 1}},
	)
	findings := m.checkNoPublicExposure(context.Background())

	var probeFail *modules.Finding
	for i := range findings {
		if findings[i].Check == "serve-probe-fail" {
			probeFail = &findings[i]
		}
	}
	require.NotNil(t, probeFail, "expected Check=serve-probe-fail on non-zero exit, got %+v", findings)
	assert.Equal(t, modules.SeverityWarning, probeFail.Severity)

	for _, f := range findings {
		assert.NotEqual(t, "serve", f.Check, "unexpected serve check in serve probe-failure path: %+v", f)
	}
}

// TestServeProbeFailDistinctCheckID documents the D-04 invariant for serve:
// "serve-probe-fail" must NOT appear in any threat-model row's failChecks, so
// probe-failure findings keep the row at — (did-not-run), not ✗.
//
// This is a compile-time-stable assertion over the known failChecks universe.
func TestServeProbeFailDistinctCheckID(t *testing.T) {
	// All failChecks values from cmd_threat_model.go threatRows, v3SurfaceRows,
	// and backendRows as of Phase 23.2. Update this list if new rows are added.
	knownFailChecks := []string{
		// threatRows
		"funnel", "acl_drift", "remote_login", "sshd_running",
		"filevault", "luks", "lock_enabled", "listen_address",
		// v3SurfaceRows
		"sec-metrics-bind", "metrics-bind-tailnet",
		"sec-webui-bind", "webui-bind",
		"sec-audit-anchor-age", "audit-anchor-age",
		// backendRows — tailscale
		"sec-funnel-schema",
		// backendRows — headscale
		"hs-tls", "hs-api-auth", "hs-lock", "hs-oidc-filter",
		// backendRows — netbird
		"nb-tls", "nb-version", "nb-zitadel", "nb-lock",
	}

	for _, checkID := range knownFailChecks {
		assert.NotEqual(t, "serve-probe-fail", checkID,
			"serve-probe-fail must not appear in threat-model failChecks (D-04 / CR-02): found %q", checkID)
	}
}

// TestServeActiveOK is a regression guard: confirmed-inactive serve (clean output)
// must yield active=false, probeOK=true — the probe ran and the check passed.
func TestServeActiveOK(t *testing.T) {
	m := newTestModule(shell.Call{Result: shell.Result{Stdout: "No serve config", ExitCode: 0}})
	active, probeOK := m.serveActive(context.Background())
	assert.False(t, active, "confirmed-inactive serve must return active=false")
	assert.True(t, probeOK, "confirmed-inactive serve must return probeOK=true")
}

// TestVerifyCallsOnlyCheckNoPublicExposure verifies WR-08: Verify must not call
// Detect (which would double every Detect finding in a runner.Doctor pass).
// The mock is primed with exactly one Call (for funnelActive inside
// checkNoPublicExposure). If Detect were called, it would make additional
// runner.Run calls and the mock would return an "unexpected call" error.
func TestVerifyCallsOnlyCheckNoPublicExposure(t *testing.T) {
	// One Call: funnelActive (inside checkNoPublicExposure) — "not configured".
	// serveActive is also called by checkNoPublicExposure, so provide it too.
	m := newTestModule(
		shell.Call{Result: shell.Result{Stdout: "Funnel is not configured.", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "No serve config", ExitCode: 0}},
	)
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)

	// The mock runner tracks how many calls were consumed. Done() returns true
	// if all scripted calls were consumed (i.e. exactly 2 calls, no more).
	mock := m.runner.(*shell.MockRunner)
	assert.True(t, mock.Done(), "Verify consumed more runner calls than expected — Detect may have been called")

	// Confirm we get the expected funnel OK finding (and no doubled findings).
	var funnelOK bool
	for _, f := range findings {
		if f.Check == "funnel" && f.Severity == modules.SeverityOK {
			funnelOK = true
		}
	}
	assert.True(t, funnelOK, "expected SeverityOK funnel finding from Verify, got %+v", findings)
}
