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
	"fmt"
	"net"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findFinding is defined in cmd_version_test.go (same package); reused here.

func TestMetricsDoctorFindingsBindAddr0000(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = true
	cfg.Observability.Metrics.BindAddr = "0.0.0.0:9090"

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry(), "")
	f, ok := findFinding(findings, "metrics-bind-tailnet")
	require.True(t, ok, "metrics-bind-tailnet finding must be present")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestMetricsDoctorFindingsBindAddrClean(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	cfg.Observability.Metrics.BindAddr = ""

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry(), "")
	f, ok := findFinding(findings, "metrics-bind-tailnet")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

func TestMetDisabledListener_NoListener(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	// Pick a free port, close it so nothing listens there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	cfg.Observability.Metrics.BindAddr = addr

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry(), "")
	f, ok := findFinding(findings, "met-disabled-listener")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

func TestMetDisabledListener_ListenerPresent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // errcheck: close error in test teardown is non-actionable
	cfg.Observability.Metrics.BindAddr = ln.Addr().String()

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry(), "")
	f, ok := findFinding(findings, "met-disabled-listener")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

// TestMetDisabledListener_StaleTailnetBound is the WR-03 regression: with an
// empty bind_addr, a stale listener bound to the tailnet IP (here a loopback
// stand-in) must still be detected by probing the resolved tailnet IP:port,
// not ":port"/127.0.0.1-by-default. The pre-fix code probed ":port" and missed
// a socket bound only to the specific IP.
func TestMetDisabledListener_StaleTailnetBound(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	cfg.Observability.Metrics.BindAddr = "" // listener would have bound tailnetIP:port

	// Bind a real socket on a specific loopback IP:port and feed that IP+port
	// as the "tailnet" address the probe should target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // errcheck: close error in test teardown is non-actionable
	tcpAddr := ln.Addr().(*net.TCPAddr)
	cfg.Observability.Metrics.Port = tcpAddr.Port

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry(), tcpAddr.IP.String())
	f, ok := findFinding(findings, "met-disabled-listener")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityFatal, f.Severity, "stale tailnet-bound listener must be detected (WR-03)")
}

func TestMetCardinality_Under500(t *testing.T) {
	cfg := config.Defaults()
	reg := metrics.NewMemRegistry()
	reg.Counter("abysslink_a", "help", map[string]string{"severity": "ok"}).Inc()
	reg.Counter("abysslink_b", "help", map[string]string{"result": "pass"}).Inc()
	reg.Gauge("abysslink_c", "help", nil).Set(1)

	findings := metricsDoctorFindings(cfg, reg, "")
	f, ok := findFinding(findings, "met-cardinality")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

func TestMetCardinality_Over500(t *testing.T) {
	cfg := config.Defaults()
	reg := metrics.NewMemRegistry()
	// 501 unique (name, label-set) series.
	for i := 0; i < 501; i++ {
		reg.Counter("abysslink_series", "help", map[string]string{"check_id": fmt.Sprintf("c%d", i)}).Inc()
	}
	findings := metricsDoctorFindings(cfg, reg, "")
	f, ok := findFinding(findings, "met-cardinality")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// TestMetBindTailnetCheck_EmptyIP_NonWildcard verifies WR-03: when the backend
// is unavailable (tailnetIP=="") and bind_addr is a non-wildcard address,
// metBindTailnetCheck must emit SeverityWarning with Check="met-bind-unknown"
// (a distinct check ID from "metrics-bind-tailnet") so the threat-model row
// renders — (did-not-run), not a false ✓.
func TestMetBindTailnetCheck_EmptyIP_NonWildcard(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = true
	cfg.Observability.Metrics.BindAddr = "192.168.1.50:9090"

	f := metBindTailnetCheck(cfg, "")

	require.Equal(t, modules.SeverityWarning, f.Severity, "expected SeverityWarning when backend unavailable and bind_addr is non-wildcard")
	require.Equal(t, "met-bind-unknown", f.Check, "expected distinct check ID met-bind-unknown (not metrics-bind-tailnet)")
	assert.NotEqual(t, "metrics-bind-tailnet", f.Check, "must not use the confirmed-tailnet-scoped check ID for an unverified address")
	assert.NotEqual(t, modules.SeverityOK, f.Severity, "must not return SeverityOK when tailnetIP is unknown")
}

// TestMetBindTailnetCheck_EmptyIP_Wildcard is the regression guard: when
// tailnetIP=="" and bind_addr is wildcard (0.0.0.0), the check must still
// return SeverityFatal (the wildcard-fatal path must not be regressed by the
// new met-bind-unknown branch).
func TestMetBindTailnetCheck_EmptyIP_Wildcard(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = true
	cfg.Observability.Metrics.BindAddr = "0.0.0.0:9090"

	f := metBindTailnetCheck(cfg, "")

	require.Equal(t, modules.SeverityFatal, f.Severity, "wildcard bind_addr must still be SeverityFatal when tailnetIP is empty")
}

// TestMetDisabledListener_UnroutableAddr verifies CR-01 / DOC-10: probing an
// unroutable address (192.0.2.1:9 — TEST-NET-1, RFC 5737, guaranteed not to
// route to any real host) must NOT return SeverityOK. The probe cannot
// distinguish "port closed" from "host unreachable", so the honest result is
// Check="met-listener-unknown" SeverityWarning.
func TestMetDisabledListener_UnroutableAddr(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	// 192.0.2.1:9 — TEST-NET-1 (RFC 5737); port 9 is the discard protocol.
	// The OS will return EHOSTUNREACH / ENETUNREACH, not ECONNREFUSED, because
	// no route exists to 192.0.2.0/24 on any standard host.
	cfg.Observability.Metrics.BindAddr = "192.0.2.1:9"

	f := metDisabledListenerCheck(cfg, "")

	// The false-OK path must not be taken when the probe is inconclusive.
	assert.NotEqual(t, modules.SeverityOK, f.Severity, "must not return SeverityOK for an unroutable address (CR-01)")
	assert.Equal(t, "met-listener-unknown", f.Check, "inconclusive probe must use the met-listener-unknown check ID")
	assert.Equal(t, modules.SeverityWarning, f.Severity, "inconclusive probe must return SeverityWarning, not SeverityOK")
	assert.NotEqual(t, "met-disabled-listener", f.Check, "must not use the confirmed-closed check ID for an unproven probe")
}

// TestMetDisabledListener_UnroutableTailnetIP verifies WR-02: the
// `case tailnetIP != ""` JoinHostPort branch (bind_addr empty, tailnetIP set)
// must honestly report met-listener-unknown when the probe is inconclusive.
// 192.0.2.2 is TEST-NET-1 (RFC 5737) — guaranteed unroutable on any standard
// host, so the dial returns EHOSTUNREACH/ENETUNREACH (not ECONNREFUSED). The
// honest result is Check="met-listener-unknown" SeverityWarning, never a false
// SeverityOK, on the address built from tailnetIP rather than an explicit
// bind_addr.
func TestMetDisabledListener_UnroutableTailnetIP(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	cfg.Observability.Metrics.BindAddr = "" // force the tailnetIP JoinHostPort branch

	f := metDisabledListenerCheck(cfg, "192.0.2.2")

	assert.NotEqual(t, modules.SeverityOK, f.Severity, "must not return SeverityOK for an unroutable tailnet IP (WR-02)")
	assert.Equal(t, "met-listener-unknown", f.Check, "inconclusive probe on the tailnetIP branch must use the met-listener-unknown check ID")
	assert.Equal(t, modules.SeverityWarning, f.Severity, "inconclusive probe must return SeverityWarning, not SeverityOK")
}

// TestMetDisabledListener_DefaultFallbackPort verifies WR-02: when both
// bind_addr and tailnetIP are empty, metDisabledListenerCheck falls back to
// dialing ":port" (the default branch at cmd_doctor.go). This pins that the
// default-fallback address is constructed from the configured port and probed:
// against a port we have proven closed (bound then released on loopback), the
// honest result is the ECONNREFUSED-gated SeverityOK on the met-disabled-listener
// check — confirming the ":port" fallback reaches a real socket address rather
// than dialing something malformed. (The inconclusive arm of the ":port" path is
// not loopback-deterministic; the tailnetIP unroutable case above pins the
// met-listener-unknown emission for inconclusive dials.)
func TestMetDisabledListener_DefaultFallbackPort(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	cfg.Observability.Metrics.BindAddr = "" // empty bind_addr ...
	// ... and empty tailnetIP forces the ":port" default fallback branch.

	// Pick a free port, then release it so nothing listens there. Dialing
	// ":port" reaches loopback and returns ECONNREFUSED for a closed port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	freePort := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	cfg.Observability.Metrics.Port = freePort

	f := metDisabledListenerCheck(cfg, "")

	assert.Equal(t, "met-disabled-listener", f.Check, "default ':port' fallback must probe the configured port and report the closed-port check ID")
	assert.Equal(t, modules.SeverityOK, f.Severity, "a provably-closed ':port' default fallback must return the ECONNREFUSED-gated SeverityOK")
}

func TestMetLabelAudit_AllAllowed(t *testing.T) {
	cfg := config.Defaults()
	reg := metrics.NewMemRegistry()
	reg.Counter("abysslink_ok", "help", map[string]string{"severity": "ok", "rig": "abc"}).Inc()

	findings := metricsDoctorFindings(cfg, reg, "")
	f, ok := findFinding(findings, "met-label-audit")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}
