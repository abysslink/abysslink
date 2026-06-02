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

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry())
	f, ok := findFinding(findings, "metrics-bind-tailnet")
	require.True(t, ok, "metrics-bind-tailnet finding must be present")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestMetricsDoctorFindingsBindAddrClean(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	cfg.Observability.Metrics.BindAddr = ""

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry())
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

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry())
	f, ok := findFinding(findings, "met-disabled-listener")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

func TestMetDisabledListener_ListenerPresent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = false
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck
	cfg.Observability.Metrics.BindAddr = ln.Addr().String()

	findings := metricsDoctorFindings(cfg, metrics.NewMemRegistry())
	f, ok := findFinding(findings, "met-disabled-listener")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestMetCardinality_Under500(t *testing.T) {
	cfg := config.Defaults()
	reg := metrics.NewMemRegistry()
	reg.Counter("abysslink_a", "help", map[string]string{"severity": "ok"}).Inc()
	reg.Counter("abysslink_b", "help", map[string]string{"result": "pass"}).Inc()
	reg.Gauge("abysslink_c", "help", nil).Set(1)

	findings := metricsDoctorFindings(cfg, reg)
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
	findings := metricsDoctorFindings(cfg, reg)
	f, ok := findFinding(findings, "met-cardinality")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

func TestMetLabelAudit_AllAllowed(t *testing.T) {
	cfg := config.Defaults()
	reg := metrics.NewMemRegistry()
	reg.Counter("abysslink_ok", "help", map[string]string{"severity": "ok", "rig": "abc"}).Inc()

	findings := metricsDoctorFindings(cfg, reg)
	f, ok := findFinding(findings, "met-label-audit")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}
