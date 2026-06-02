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

package daemon_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/metrics"
)

// localMockBackend is a minimal backend.Client whose IP returns a fixed address.
// Only IP is exercised by the metrics server; every other method is a stub that
// is never called in these tests.
type localMockBackend struct {
	ip    string
	ipErr error
}

func (m *localMockBackend) Status(_ context.Context) (*backend.Status, error) { return nil, nil }
func (m *localMockBackend) IP(_ context.Context) (string, error)              { return m.ip, m.ipErr }
func (m *localMockBackend) Hostname(_ context.Context) (string, error)        { return "", nil }
func (m *localMockBackend) SSHConfig() backend.SSHConfig                      { return backend.SSHConfig{} }
func (m *localMockBackend) LockCapability() backend.LockCapability            { return backend.LockCapability("") }
func (m *localMockBackend) Capabilities() backend.Capabilities                { return backend.Capabilities{} }
func (m *localMockBackend) Up(_ context.Context, _ backend.UpOpts) error      { return nil }
func (m *localMockBackend) Set(_ context.Context, _ backend.SetOpts) error    { return nil }
func (m *localMockBackend) Down(_ context.Context) error                      { return nil }

func metricsEnabledCfg(port int) *config.Config {
	cfg := config.Defaults()
	cfg.Observability.Metrics.Enabled = true
	cfg.Observability.Metrics.Port = port
	cfg.Tailnet.Hostname = "test-rig"
	return cfg
}

// freePort returns an available TCP port on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func TestMetricsServerDisabled(t *testing.T) {
	cfg := config.Defaults() // Enabled defaults false
	port := freePort(t)
	cfg.Observability.Metrics.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	daemon.StartMetricsServer(ctx, cfg, metrics.NewMemRegistry(), &localMockBackend{ip: "127.0.0.1"})

	// No listener should bind.
	_, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 50*time.Millisecond)
	assert.Error(t, err, "no listener should be bound when metrics disabled")
}

func TestMetricsServerNilBackend(t *testing.T) {
	cfg := metricsEnabledCfg(freePort(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var b backend.Client // nil interface value

	require.NotPanics(t, func() {
		daemon.StartMetricsServer(ctx, cfg, metrics.NewMemRegistry(), b)
		time.Sleep(100 * time.Millisecond)
	})

	_, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(cfg.Observability.Metrics.Port)), 50*time.Millisecond)
	assert.Error(t, err, "no listener should bind with nil backend")
}

func TestMetricsServerBindsTailnetIP(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := metrics.NewMemRegistry()
	reg.Gauge("test_up", "up", nil).Set(1)
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	body := waitForMetrics(t, port)
	assert.NotEmpty(t, body) // a 200 with a non-empty body confirms the bind
}

func TestMetricsFormat_HELP_TYPE(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)
	reg := metrics.NewMemRegistry()
	reg.Counter("test_total", "a test counter", nil).Inc()
	reg.Gauge("test_up", "a test gauge", nil).Set(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	body := waitForMetrics(t, port)
	assert.Contains(t, body, "# HELP test_total a test counter")
	assert.Contains(t, body, "# TYPE test_total counter")
	assert.Contains(t, body, "# HELP test_up a test gauge")
	assert.Contains(t, body, "# TYPE test_up gauge")
}

func TestMetricsFormat_ContentType(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)
	reg := metrics.NewMemRegistry()
	reg.Gauge("test_up", "up", nil).Set(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	ct := waitForMetricsContentType(t, port)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", ct)
}

func TestMetricsFormat_LabelEscape(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)
	reg := metrics.NewMemRegistry()
	reg.Counter("test_total", "c", map[string]string{"rig": "a\\b\"c\nd"}).Inc()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	body := waitForMetrics(t, port)
	assert.Contains(t, body, `rig="a\\b\"c\nd"`)
}

func TestMetricsFormat_FinalNewline(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)
	reg := metrics.NewMemRegistry()
	reg.Gauge("test_up", "up", nil).Set(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	body := waitForMetrics(t, port)
	require.NotEmpty(t, body)
	assert.True(t, strings.HasSuffix(body, "\n"), "body must end with newline")
}

func TestMetricsFormat_NoLabels(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)
	reg := metrics.NewMemRegistry()
	reg.Gauge("test_up", "up", nil).Set(2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	body := waitForMetrics(t, port)
	assert.Contains(t, body, "test_up 2\n")
	assert.NotContains(t, body, "test_up{}")
}

func TestMetricsFormat_FloatG(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)
	reg := metrics.NewMemRegistry()
	reg.Gauge("test_up", "up", nil).Set(3.14)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	body := waitForMetrics(t, port)
	assert.Contains(t, body, "test_up 3.14\n")
}

func TestMetricsServerShutdown(t *testing.T) {
	port := freePort(t)
	cfg := metricsEnabledCfg(port)
	reg := metrics.NewMemRegistry()
	reg.Gauge("test_up", "up", nil).Set(1)

	ctx, cancel := context.WithCancel(context.Background())
	daemon.StartMetricsServer(ctx, cfg, reg, &localMockBackend{ip: "127.0.0.1"})

	// Ensure it is up first.
	_ = waitForMetrics(t, port)

	cancel()

	// Within 500ms the port must be closed.
	deadline := time.Now().Add(500 * time.Millisecond)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 50*time.Millisecond)
		if err != nil {
			lastErr = err
			break
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	assert.Error(t, lastErr, "listener should be closed within 500ms of cancel")
}

func TestRegisterOBS05Metrics(t *testing.T) {
	reg := metrics.NewMemRegistry()
	daemon.RegisterOBS05Metrics(reg, "test-rig", true, 1, 2, true, time.Now().Add(time.Hour), time.Now())

	snap := reg.Snapshot()
	names := map[string]bool{}
	for _, f := range snap {
		names[f.Name] = true
	}
	assert.True(t, names["abysslink_rig_reachable"], "rig_reachable present")
	assert.True(t, names["abysslink_doctor_findings"], "doctor_findings present")
	assert.True(t, names["abysslink_lock_status"], "lock_status present")
	assert.True(t, names["abysslink_cert_expiry_seconds"], "cert_expiry_seconds present")
	assert.True(t, names["abysslink_last_seen_timestamp"], "last_seen_timestamp present")
}

// --- test helpers ---

func itoa(i int) string {
	return strings.TrimSpace(formatInt(i))
}

func formatInt(i int) string {
	// avoid strconv import churn in the test by using fmt-free conversion
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func waitForMetrics(t *testing.T, port int) string {
	t.Helper()
	url := "http://127.0.0.1:" + itoa(port) + "/metrics"
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec,noctx // test-local fixed URL
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return string(b)
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	require.NoError(t, lastErr, "metrics endpoint never returned 200")
	return ""
}

func waitForMetricsContentType(t *testing.T, port int) string {
	t.Helper()
	url := "http://127.0.0.1:" + itoa(port) + "/metrics"
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec,noctx // test-local fixed URL
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		ct := resp.Header.Get("Content-Type")
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return ct
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("metrics endpoint never returned 200")
	return ""
}
