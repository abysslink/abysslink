//go:build webui

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

package webui

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/safeweb"
	"tailscale.com/tailcfg"
)

// mockWhoIs is a test double for the WhoIs seam. It records whether WhoIs was
// invoked so loopback tests can assert the gate short-circuits BEFORE any
// daemon call (WEB-04: loopback is rejected without consulting WhoIs).
type mockWhoIs struct {
	resp   *apitype.WhoIsResponse
	err    error
	called bool
}

func (m *mockWhoIs) WhoIs(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
	m.called = true
	return m.resp, m.err
}

// okNext is a trivial 200 handler used as the protected resource behind the
// middleware; reaching it means the gate allowed the request through.
func okNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestLoopback403(t *testing.T) {
	m := &mockWhoIs{resp: validWhoIs()}
	h := whoIsMiddleware(m, okNext())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "loopback must be 403 (WEB-04)")
	assert.False(t, m.called, "WhoIs must NOT be consulted for loopback — the IP gate is first")
}

func TestLoopbackIPv6403(t *testing.T) {
	m := &mockWhoIs{resp: validWhoIs()}
	h := whoIsMiddleware(m, okNext())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "IPv6 loopback must be 403 (WEB-04)")
	assert.False(t, m.called, "WhoIs must NOT be consulted for IPv6 loopback")
}

func TestWhoIsNotFound403(t *testing.T) {
	m := &mockWhoIs{err: local.ErrPeerNotFound}
	h := whoIsMiddleware(m, okNext())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "100.64.0.5:40000" // tailnet CGNAT range, non-loopback
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "ErrPeerNotFound must be 403 (WEB-04)")
	assert.True(t, m.called, "WhoIs is consulted for a non-loopback peer")
}

func TestWhoIsNilProfile403(t *testing.T) {
	// Pitfall 3: a peer with a nil UserProfile must not pass and must not panic.
	m := &mockWhoIs{resp: &apitype.WhoIsResponse{Node: &tailcfg.Node{}, UserProfile: nil}}
	h := whoIsMiddleware(m, okNext())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "nil UserProfile must be 403 (Pitfall 3)")
}

func TestWhoIsSuccessPasses(t *testing.T) {
	m := &mockWhoIs{resp: validWhoIs()}
	h := whoIsMiddleware(m, okNext())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "an identified tailnet peer must pass")
}

func TestCSRFMissing403(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /notify", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	sw, err := newSafewebServer(mux)
	require.NoError(t, err)

	srv := httptest.NewServer(sw)
	defer srv.Close()

	// POST without a CSRF token must be rejected by safeweb's BrowserMux.
	resp, err := http.Post(srv.URL+"/notify", "application/x-www-form-urlencoded", strings.NewReader(""))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "POST without CSRF token must be 403 (WEB-05)")
}

func TestReadOnlyBlock(t *testing.T) {
	cfg := &config.WebUIConfig{ReadOnly: true, AllowNotify: false}
	h := readOnlyMiddleware(cfg, okNext())

	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodPost} {
		req := httptest.NewRequest(method, "/notify", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s must be blocked when allow_notify=false (WEB-02)", method)
	}

	// GET always passes the read-only gate.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "GET must always pass the read-only gate")
}

func TestReadOnlyAllowNotify(t *testing.T) {
	cfg := &config.WebUIConfig{ReadOnly: true, AllowNotify: true}
	h := readOnlyMiddleware(cfg, okNext())

	// With allow_notify=true, POST /notify passes the read-only gate (CSRF is
	// enforced separately by safeweb below this middleware).
	req := httptest.NewRequest(http.MethodPost, "/notify", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "POST /notify must pass when allow_notify=true")

	// But a POST to any other path is still blocked.
	req2 := httptest.NewRequest(http.MethodPost, "/other", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusForbidden, rec2.Code, "POST to a non-notify path must stay blocked")
}

func TestRingBuffer(t *testing.T) {
	rb := NewNotifyRingBuffer()
	for i := 0; i < 150; i++ {
		rb.Add(NotifyEvent{Title: "event", Topic: "rig", Priority: "default", Time: time.Now()})
	}
	snap := rb.Snapshot()
	assert.Len(t, snap, 100, "ring must retain exactly capacity (100) events (WEB-07)")
}

func TestRingBufferNewestFirst(t *testing.T) {
	rb := NewNotifyRingBuffer()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		rb.Add(NotifyEvent{Title: "e", Time: base.Add(time.Duration(i) * time.Minute)})
	}
	snap := rb.Snapshot()
	require.Len(t, snap, 5)
	assert.True(t, snap[0].Time.After(snap[1].Time), "Snapshot must be newest-first")
}

func TestAuditProjection(t *testing.T) {
	entries := []audit.Entry{
		{
			Time:     time.Date(2026, 6, 2, 14, 3, 12, 0, time.UTC),
			Op:       "write",
			Target:   "abysslink.yaml",
			DryRun:   true,
			Hash:     "deadbeef",
			PrevHash: "cafef00d",
			Sig:      "signature-bytes",
		},
	}
	views := projectAuditEntries(entries, 200)
	require.Len(t, views, 1)
	assert.Equal(t, "write", views[0].Op)
	assert.Equal(t, "abysslink.yaml", views[0].Target)
	assert.True(t, views[0].DryRun)
	assert.Equal(t, "2026-06-02 14:03:12", views[0].Time)

	// WEB-07 HARD FLOOR: the projection struct must NOT carry Hash/PrevHash/Sig
	// (nor any body/content field). Assert via reflection that no such field
	// name is reachable on AuditEntryView.
	typ := reflect.TypeOf(AuditEntryView{})
	forbidden := []string{"Hash", "PrevHash", "Sig", "Body", "Content", "Data"}
	for _, name := range forbidden {
		_, ok := typ.FieldByName(name)
		assert.False(t, ok, "AuditEntryView must not have a %q field (WEB-07, AUD-04)", name)
	}
}

func TestAuditProjectionLimit(t *testing.T) {
	entries := make([]audit.Entry, 10)
	for i := range entries {
		entries[i] = audit.Entry{Op: "write", Target: "f", Time: time.Now()}
	}
	views := projectAuditEntries(entries, 3)
	assert.Len(t, views, 3, "limit must cap the projected entries to the last N")
}

func TestTLSProbeFailClose(t *testing.T) {
	cfg := config.Defaults()
	cfg.WebUI.Enabled = true
	cfg.Backend.Type = "headscale" // GetCertificate is unimplemented here (#2137)

	m := New(modules.Deps{Cfg: cfg})
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)

	var tlsFinding *modules.Finding
	for i := range findings {
		if findings[i].Check == "webui-tls" {
			tlsFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, tlsFinding, "Verify must emit a webui-tls finding on a non-Tailscale backend")
	assert.Equal(t, modules.SeverityFatal, tlsFinding.Severity, "webui-tls must be FATAL on headscale (WEB-03 fail-closed)")

	// Fail-closed: no listener may be bound on the configured webui address.
	addr := webuiAddr(cfg)
	conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		t.Fatalf("a listener is bound on %s but TLS probe should have failed closed", addr)
	}
}

func TestVerifyTailscaleNoTLSFatal(t *testing.T) {
	// On a Tailscale backend the backend-type gate must NOT itself emit a
	// webui-tls FATAL; the eager cert probe may still warn, but the
	// backend-conditional path is the one under test here.
	cfg := config.Defaults()
	cfg.WebUI.Enabled = true
	cfg.Backend.Type = "tailscale"

	m := New(modules.Deps{Cfg: cfg})
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)

	for _, f := range findings {
		if f.Check == "webui-tls" && f.Severity == modules.SeverityFatal {
			assert.Contains(t, f.Message, "cert", "a Tailscale-backend webui-tls FATAL must be about cert availability, not backend type")
		}
	}
}

func TestModuleDisabledByDefault(t *testing.T) {
	cfg := config.Defaults() // WebUI.Enabled defaults false
	m := New(modules.Deps{Cfg: cfg})
	detected, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, detected, "a disabled webui module reports no findings from Detect")

	plan, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, plan, "a disabled webui module plans no actions")
}

func TestBuildCSPSelfOnly(t *testing.T) {
	csp := buildCSP()
	got := csp["default-src"]
	require.NotEmpty(t, got)
	assert.Equal(t, []string{"'self'"}, got, "default-src must be 'self' only — no unsafe-inline, no CDN (WEB-06)")
	assert.NotContains(t, csp.String(), "unsafe-inline", "CSP must never permit unsafe-inline")
}

// validWhoIs returns a WhoIsResponse with a populated UserProfile, the shape
// tailscaled returns for an authenticated tailnet peer.
func validWhoIs() *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com", DisplayName: "Alice"},
	}
}

// compile-time assertion that the module satisfies the Module interface.
var _ modules.Module = (*Module)(nil)

// safeweb.Server must implement http.Handler (used as the inner handler).
var _ http.Handler = (*safeweb.Server)(nil)
