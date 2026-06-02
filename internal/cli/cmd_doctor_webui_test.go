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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webuiBaseConfig returns a config with a webui-enabled, otherwise-valid
// WebUIConfig so each sub-test isolates a single check. Live-probe seams are
// disabled (set to OK) unless the test overrides them.
func webuiBaseConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "tailscale"
	cfg.WebUI.Enabled = true
	cfg.WebUI.ReadOnly = true
	cfg.WebUI.BindAddr = "100.64.0.1:8443"
	return cfg
}

// --- webui-bind ---

func TestWebuiBindCheck(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.BindAddr = "0.0.0.0:8443"
	f := webuiBindCheck(cfg)
	assert.Equal(t, "webui-bind", f.Check)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestWebuiBindCheckPass(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.BindAddr = "100.64.0.1:8443"
	f := webuiBindCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

func TestWebuiBindCheckDisabled(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.Enabled = false
	cfg.WebUI.BindAddr = "100.64.0.1:8443"
	f := webuiBindCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

// --- webui-mutations-disabled ---

func TestWebuiMutationsDisabledCheck(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.ReadOnly = false
	f := webuiMutationsDisabledCheck(cfg)
	assert.Equal(t, "webui-mutations-disabled", f.Check)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestWebuiMutationsDisabledPass(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.ReadOnly = true
	f := webuiMutationsDisabledCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

// --- webui-funnel ---

func TestWebuiFunnelCheck(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.BindAddr = ""
	f := webuiFunnelCheck(cfg)
	assert.Equal(t, "webui-funnel", f.Check)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestWebuiFunnelCheckPass(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.BindAddr = "100.64.0.1:8443"
	f := webuiFunnelCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

// --- webui-tls ---

func TestWebuiTLSCheckNonTailscale(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.Backend.Type = "headscale"
	f := webuiTLSCheck(cfg)
	assert.Equal(t, "webui-tls", f.Check)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestWebuiTLSCheckNetBird(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.Backend.Type = "netbird"
	f := webuiTLSCheck(cfg)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestWebuiTLSCheckTailscale(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.Backend.Type = "tailscale"
	cfg.WebUI.Enabled = false
	f := webuiTLSCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

// --- webui-whoami-local ---

func TestWebuiWhoamiLocalTransportError(t *testing.T) {
	cfg := webuiBaseConfig()
	// A transport error means tailscaled localapi is unreachable = FATAL.
	probe := func(_ context.Context) error { return errors.New("dial unix: connection refused") }
	f := webuiWhoamiLocalCheck(context.Background(), cfg, probe)
	assert.Equal(t, "webui-whoami-local", f.Check)
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestWebuiWhoamiLocalPeerNotFound(t *testing.T) {
	cfg := webuiBaseConfig()
	// ErrPeerNotFound means localapi IS reachable; the dummy addr is simply not
	// a real peer — expected and OK.
	probe := func(_ context.Context) error { return errWhoamiPeerNotFound }
	f := webuiWhoamiLocalCheck(context.Background(), cfg, probe)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

// --- webui-csrf ---

func TestWebuiCSRFLiveProbe(t *testing.T) {
	// A server that returns 403 to an unauthenticated POST (CSRF active).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := webuiBaseConfig()
	f := webuiCSRFCheck(context.Background(), cfg, srv.URL)
	assert.Equal(t, "webui-csrf", f.Check)
	assert.Equal(t, modules.SeverityOK, f.Severity)

	// A server that returns 200 (CSRF NOT active) must FATAL.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer bad.Close()
	fb := webuiCSRFCheck(context.Background(), cfg, bad.URL)
	assert.Equal(t, modules.SeverityFatal, fb.Severity)

	// Unreachable address must FATAL.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := "http://" + ln.Addr().String()
	require.NoError(t, ln.Close())
	fu := webuiCSRFCheck(context.Background(), cfg, addr)
	assert.Equal(t, modules.SeverityFatal, fu.Severity)
}

func TestWebuiCSRFNotEnabled(t *testing.T) {
	cfg := webuiBaseConfig()
	cfg.WebUI.Enabled = false
	f := webuiCSRFCheck(context.Background(), cfg, "")
	assert.Equal(t, modules.SeverityOK, f.Severity)
}

// --- aggregate ---

func TestWebuiDoctorFindingsAllEight(t *testing.T) {
	cfg := webuiBaseConfig()
	findings := webuiDoctorFindings(context.Background(), cfg)
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.Check] = true
	}
	for _, want := range []string{
		"webui-bind", "webui-funnel", "webui-mutations-disabled", "webui-tls",
		"webui-auth", "webui-whoami-local", "webui-csrf", "webui-csp",
	} {
		assert.True(t, ids[want], "expected webui doctor check %q", want)
	}
}
