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

package daemon

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
)

// TestMetricsHandlerNilRegistry is the WR-04 regression: a nil Registry must not
// panic the handler (CLAUDE.md: no panics in normal control flow). It returns a
// 200 with the strict content type and an empty body.
func TestMetricsHandlerNilRegistry(t *testing.T) {
	h := metricsHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	assert.NotPanics(t, func() { h(rec, req) })

	res := rec.Result()
	defer res.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, metricsContentType, res.Header.Get("Content-Type"))
	assert.Empty(t, rec.Body.String(), "nil registry yields an empty exposition")
}

// ipOnlyBackend is a minimal backend.Client whose IP returns a fixed address.
// resolveMetricsAddr only touches IP; every other method is an unused stub.
type ipOnlyBackend struct {
	ip    string
	ipErr error
}

func (m *ipOnlyBackend) Status(context.Context) (*backend.Status, error)  { return nil, nil }
func (m *ipOnlyBackend) IP(context.Context) (string, error)               { return m.ip, m.ipErr }
func (m *ipOnlyBackend) Hostname(context.Context) (string, error)         { return "", nil }
func (m *ipOnlyBackend) SSHConfig() backend.SSHConfig                      { return backend.SSHConfig{} }
func (m *ipOnlyBackend) LockCapability() backend.LockCapability            { return backend.LockCapability("") }
func (m *ipOnlyBackend) Capabilities() backend.Capabilities               { return backend.Capabilities{} }
func (m *ipOnlyBackend) Up(context.Context, backend.UpOpts) error          { return nil }
func (m *ipOnlyBackend) Set(context.Context, backend.SetOpts) error        { return nil }
func (m *ipOnlyBackend) Down(context.Context) error                        { return nil }

// TestResolveMetricsAddrTailnetFloor is the WR-01 regression for the
// backend-agnostic OBS-03 floor: an explicit bind_addr is accepted only when its
// host equals the backend-resolved tailnet IP. The cases cover Tailscale CGNAT
// and Headscale/NetBird-style ULA addresses, a mismatch, and a public IP.
func TestResolveMetricsAddrTailnetFloor(t *testing.T) {
	const port = 9090
	cases := []struct {
		name       string
		backendIP  string
		bindAddr   string
		wantOK     bool
		wantAddr   string // checked only when wantOK
	}{
		{
			name:      "empty bind_addr binds backend CGNAT IP",
			backendIP: "100.64.0.1",
			bindAddr:  "",
			wantOK:    true,
			wantAddr:  "100.64.0.1:9090",
		},
		{
			name:      "bind_addr matching CGNAT IP accepted",
			backendIP: "100.64.0.1",
			bindAddr:  "100.64.0.1",
			wantOK:    true,
			wantAddr:  "100.64.0.1:9090",
		},
		{
			name:      "bind_addr matching ULA IP accepted (Headscale/NetBird-style)",
			backendIP: "fd7a:115c:a1e0::1234",
			bindAddr:  "fd7a:115c:a1e0::1234",
			wantOK:    true,
			wantAddr:  "[fd7a:115c:a1e0::1234]:9090",
		},
		{
			name:      "bind_addr with own port matching ULA IP accepted",
			backendIP: "fd7a:115c:a1e0::1234",
			bindAddr:  "[fd7a:115c:a1e0::1234]:7777",
			wantOK:    true,
			wantAddr:  "[fd7a:115c:a1e0::1234]:7777",
		},
		{
			name:      "public IP rejected",
			backendIP: "100.64.0.1",
			bindAddr:  "203.0.113.7",
			wantOK:    false,
		},
		{
			name:      "loopback mismatch rejected",
			backendIP: "100.64.0.1",
			bindAddr:  "127.0.0.1",
			wantOK:    false,
		},
		{
			name:      "wildcard rejected",
			backendIP: "100.64.0.1",
			bindAddr:  "0.0.0.0",
			wantOK:    false,
		},
		{
			name:      "ipv6 wildcard rejected",
			backendIP: "fd7a:115c:a1e0::1234",
			bindAddr:  "::",
			wantOK:    false,
		},
		{
			name:      "different ULA rejected",
			backendIP: "fd7a:115c:a1e0::1234",
			bindAddr:  "fd7a:115c:a1e0::9999",
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Observability.Metrics.Enabled = true
			cfg.Observability.Metrics.Port = port
			cfg.Observability.Metrics.BindAddr = tc.bindAddr

			addr, ok := resolveMetricsAddr(context.Background(), cfg, &ipOnlyBackend{ip: tc.backendIP})
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantAddr, addr)
				// The resolved host must equal the backend tailnet IP.
				host := config.BindAddrHost(addr)
				assert.True(t, net.ParseIP(host).Equal(net.ParseIP(tc.backendIP)),
					"resolved host %q must equal backend IP %q", host, tc.backendIP)
			}
		})
	}
}
