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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestCSRFCrossOriginBlocked(t *testing.T) {
	// CrossOriginProtection (DEP-03 replacement for gorilla/csrf) blocks cross-origin
	// POSTs via Sec-Fetch-Site: cross-site. A POST carrying that header must be 403.
	// Requests with no Sec-Fetch-Site (e.g. doctor probe) are treated as same-origin
	// (non-browser) and allowed (per RESEARCH.md Pitfall 2).
	mux := http.NewServeMux()
	mux.HandleFunc("POST /notify", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := buildWebHandler(mux)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// POST with Sec-Fetch-Site: cross-site must be rejected by CrossOriginProtection.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/notify", strings.NewReader(""))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "cross-origin POST must be 403 (DEP-03 / WEB-05)")
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

	// Fail-closed: no listener may be bound on the resolved webui address.
	addr, ok := resolveWebUIAddr(context.Background(), cfg, stubTailnetResolver{ip: "100.64.0.1"})
	require.True(t, ok, "resolveWebUIAddr must succeed for a valid tailnet IP")
	conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		t.Fatalf("a listener is bound on %s but TLS probe should have failed closed", addr)
	}
}

// stubTailnetResolver is a test double for tailnetIPResolver: it returns a fixed
// IP (and optional error) without consulting a live tailscaled.
type stubTailnetResolver struct {
	ip  string
	err error
}

func (s stubTailnetResolver) IP(_ context.Context) (string, error) {
	return s.ip, s.err
}

func TestResolveWebUIAddrFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		bindAddr string
		resolver stubTailnetResolver
		wantOK   bool
		wantAddr string
	}{
		{
			name:     "empty bind_addr resolves to tailnet IP",
			bindAddr: "",
			resolver: stubTailnetResolver{ip: "100.64.0.7"},
			wantOK:   true,
			wantAddr: "100.64.0.7:8443",
		},
		{
			name:     "empty tailnet IP fails closed (no wildcard bind)",
			bindAddr: "",
			resolver: stubTailnetResolver{ip: ""},
			wantOK:   false,
		},
		{
			name:     "resolver error fails closed",
			bindAddr: "",
			resolver: stubTailnetResolver{err: assert.AnError},
			wantOK:   false,
		},
		{
			name:     "unspecified resolved IP fails closed",
			bindAddr: "",
			resolver: stubTailnetResolver{ip: "0.0.0.0"},
			wantOK:   false,
		},
		{
			name:     "explicit bind_addr matching tailnet IP is accepted",
			bindAddr: "100.64.0.7",
			resolver: stubTailnetResolver{ip: "100.64.0.7"},
			wantOK:   true,
			wantAddr: "100.64.0.7:8443",
		},
		{
			name:     "explicit wildcard bind_addr fails closed",
			bindAddr: "0.0.0.0",
			resolver: stubTailnetResolver{ip: "100.64.0.7"},
			wantOK:   false,
		},
		{
			name:     "explicit bind_addr mismatching tailnet IP fails closed",
			bindAddr: "10.0.0.1",
			resolver: stubTailnetResolver{ip: "100.64.0.7"},
			wantOK:   false,
		},
		{
			name:     "explicit bind_addr with embedded port is honored",
			bindAddr: "100.64.0.7:9443",
			resolver: stubTailnetResolver{ip: "100.64.0.7"},
			wantOK:   true,
			wantAddr: "100.64.0.7:9443",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.WebUI.Enabled = true
			cfg.WebUI.BindAddr = tc.bindAddr
			addr, ok := resolveWebUIAddr(context.Background(), cfg, tc.resolver)
			assert.Equal(t, tc.wantOK, ok, "fail-closed decision (WEB-02)")
			if tc.wantOK {
				assert.Equal(t, tc.wantAddr, addr, "resolved bind address")
			} else {
				assert.Empty(t, addr, "no address may be returned when failing closed (WEB-02)")
			}
		})
	}
}

func TestStaticAssetsServed(t *testing.T) {
	mux := http.NewServeMux()
	ServeStaticAssets(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		path            string
		wantContentType string // substring
	}{
		{"/static/style.css", "css"},
		{"/static/htmx.min.js", "javascript"},
		{"/static/error-handler.js", "javascript"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode, "embedded asset must be served, not 404 (CR-02)")
			assert.Contains(t, resp.Header.Get("Content-Type"), tc.wantContentType,
				"asset must carry the correct content-type")
		})
	}

	// The templates/ subtree must NOT be reachable under /static/ (CR-02).
	resp, err := http.Get(srv.URL + "/static/base.html")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "templates must not be exposed under /static/")
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

func TestSecurityHeadersCSP(t *testing.T) {
	// securityHeadersMiddleware must set a CSP that pins default-src 'self',
	// contains frame-ancestors 'none', and never permits unsafe-inline (WEB-06).
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := buildWebHandler(mux)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/") //nolint:noctx // test-only plain GET
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	csp := resp.Header.Get("Content-Security-Policy")
	require.NotEmpty(t, csp, "every response must carry a CSP header (WEB-06)")
	assert.Contains(t, csp, "default-src 'self'", "CSP must pin default-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'", "CSP must block framing (WEB-06)")
	assert.NotContains(t, csp, "unsafe-inline", "CSP must never permit unsafe-inline")
}

// validWhoIs returns a WhoIsResponse with a populated UserProfile, the shape
// tailscaled returns for an authenticated tailnet peer.
func validWhoIs() *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com", DisplayName: "Alice"},
	}
}

// --- Plan 03: handler + CSP + template tests ---

// stubStatusProvider returns a fixed status snapshot for handler tests.
type stubStatusProvider struct {
	online int
	total  int
	rigs   []rigRow
}

func (s stubStatusProvider) FleetStatus(_ context.Context) (int, int, []rigRow) {
	return s.online, s.total, s.rigs
}

// stubDoctorProvider returns fixed findings for handler tests.
type stubDoctorProvider struct {
	findings []modules.Finding
}

func (s stubDoctorProvider) DoctorFindings(_ context.Context) []modules.Finding {
	return s.findings
}

// newTestHandlers builds a Handlers with stub providers and a temp audit log.
func newTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	h, err := NewHandlers(HandlerDeps{
		Status: stubStatusProvider{
			online: 1, total: 1,
			rigs: []rigRow{{Name: "rig-a", StatusClass: "dot-online", StatusLabel: "online", LastSeen: "2m ago", CertClass: "", CertDays: "90d", LockClass: "lock-ok", LockStatus: "Locked"}},
		},
		Doctor: stubDoctorProvider{findings: []modules.Finding{
			{Module: "ssh", Check: "ssh-checkperiod", Severity: modules.SeverityFatal, Message: "checkPeriod too long"},
			{Module: "net", Check: "net-bind", Severity: modules.SeverityWarning, Message: "bind addr broad"},
			{Module: "fs", Check: "fs-encrypt", Severity: modules.SeverityOK, Message: "disk encrypted"},
		}},
		Ring:         NewNotifyRingBuffer(),
		AuditLogPath: "",
		RigHostname:  "rig-a",
	})
	require.NoError(t, err)
	return h
}

func TestCSPHeader(t *testing.T) {
	h := newTestHandlers(t)
	mux := http.NewServeMux()
	h.Register(mux)
	handler := buildWebHandler(mux)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/") //nolint:noctx // test-only plain GET
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	csp := resp.Header.Get("Content-Security-Policy")
	require.NotEmpty(t, csp, "every response must carry a CSP header (WEB-06)")
	assert.Contains(t, csp, "default-src 'self'", "CSP must pin default-src 'self'")
	assert.NotContains(t, csp, "unsafe-inline", "CSP must never permit unsafe-inline (WEB-06 HARD FLOOR)")
}

func TestAuditTemplateNoHashes(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.log"
	// Two entries carrying secret chain fields that must NEVER render.
	const secretHash = "sha256:deadbeefcafef00ddeadbeefcafef00d"
	entries := []audit.Entry{
		{Time: time.Now(), Op: "write", Target: "abysslink.yaml", DryRun: true, Hash: secretHash, PrevHash: secretHash, Sig: "secret-sig"},
		{Time: time.Now(), Op: "read", Target: "config.yaml", Hash: secretHash, Sig: "secret-sig"},
	}
	writeAuditLog(t, logPath, entries)

	h, err := NewHandlers(HandlerDeps{
		Status: stubStatusProvider{}, Doctor: stubDoctorProvider{},
		Ring: NewNotifyRingBuffer(), AuditLogPath: logPath, RigHostname: "rig-a",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.handleAudit(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, "sha256:", "audit HTML must never contain a hash prefix (WEB-07 HARD FLOOR)")
	assert.NotContains(t, body, "deadbeef", "audit HTML must never contain Hash/PrevHash bytes")
	assert.NotContains(t, body, "secret-sig", "audit HTML must never contain Sig bytes")
	// The permitted projection fields still render.
	assert.Contains(t, body, "abysslink.yaml")
	assert.Contains(t, body, "write")
}

func TestStatusFragment(t *testing.T) {
	h := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/status-fragment", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.handleStatusFragment(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "status-panel", "fragment must contain the htmx swap div id")
	assert.Contains(t, rec.Body.String(), "every 10s", "fragment must carry the 10s auto-poll trigger")
}

func TestDoctorView(t *testing.T) {
	h := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/doctor", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.handleDoctor(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "FATAL", "doctor view must show the FATAL severity group")
	assert.Contains(t, body, "WARN", "doctor view must show the WARNING severity group")
}

func TestNotifyView(t *testing.T) {
	ring := NewNotifyRingBuffer()
	ring.Add(NotifyEvent{Time: time.Now(), Title: "Build finished", Topic: "rig-a", Priority: "high"})
	h, err := NewHandlers(HandlerDeps{
		Status: stubStatusProvider{}, Doctor: stubDoctorProvider{},
		Ring: ring, AuditLogPath: "", RigHostname: "rig-a",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/notify", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.handleNotify(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Build finished", "notify view must render the event title")
}

func TestRenderErrorView(t *testing.T) {
	h := newTestHandlers(t)

	// Full-page error render.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.renderError(rec, req, http.StatusNotFound, "Not found", "no such page")

	require.Equal(t, http.StatusNotFound, rec.Code, "renderError must write the status code")
	body := rec.Body.String()
	assert.Contains(t, body, "Not found", "error view must render the heading")
	assert.Contains(t, body, "no such page", "error view must render the message")
	assert.Contains(t, body, "<html", "full-page error render must include the base shell")

	// Partial (htmx) error render renders only the content block.
	preq := httptest.NewRequest(http.MethodGet, "/", nil)
	preq.RemoteAddr = "100.64.0.5:40000"
	preq.Header.Set("HX-Request", "true")
	prec := httptest.NewRecorder()
	h.renderError(prec, preq, http.StatusInternalServerError, "Boom", "internal")
	assert.Equal(t, http.StatusInternalServerError, prec.Code)
	assert.Contains(t, prec.Body.String(), "Boom")
	assert.NotContains(t, prec.Body.String(), "<html", "partial error render must omit the base shell")
}

func TestNotifyFormNoCSRFToken(t *testing.T) {
	// DEP-03: With CrossOriginProtection replacing gorilla/csrf, the notify form
	// must NOT contain a hidden gorilla CSRF token field. CrossOriginProtection is
	// stateless — no token injection required (WR-02 / DEP-03).
	h, err := NewHandlers(HandlerDeps{
		Status: stubStatusProvider{}, Doctor: stubDoctorProvider{},
		Ring: NewNotifyRingBuffer(), AuditLogPath: "", RigHostname: "rig-a",
		AllowNotify: true,
	})
	require.NoError(t, err)
	mux := http.NewServeMux()
	h.Register(mux)
	handler := buildWebHandler(mux)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/notify") //nolint:noctx // test-only plain GET
	require.NoError(t, err)
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	body := string(bodyBytes)

	// The form must render (allow_notify=true).
	assert.Contains(t, body, `action="/notify"`, "notify form must be present when allow_notify=true")
	// No gorilla hidden token must appear — CrossOriginProtection is stateless.
	assert.NotContains(t, body, `name="gorilla.csrf.Token"`, "gorilla CSRF token must NOT be in the form (DEP-03)")

	// A same-origin POST (no Sec-Fetch-Site header, like a direct client) must
	// pass CrossOriginProtection and reach handleNotifyPost (returns 501 scaffold).
	req, rerr := http.NewRequest(http.MethodPost, srv.URL+"/notify", strings.NewReader("title=hello"))
	require.NoError(t, rerr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResp, derr := http.DefaultClient.Do(req)
	require.NoError(t, derr)
	_ = postResp.Body.Close()
	assert.Equal(t, http.StatusNotImplemented, postResp.StatusCode,
		"same-origin POST must reach handleNotifyPost (501 scaffold) — CrossOriginProtection allows non-cross-site requests")
}

func TestSecurityHeaders(t *testing.T) {
	// securityHeadersMiddleware must set all five required security headers on
	// every response (DEP-03 / T-22-14).
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := buildWebHandler(mux)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/") //nolint:noctx // test-only plain GET
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.NotEmpty(t, resp.Header.Get("Content-Security-Policy"), "CSP header must be set")
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "same-origin", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, "same-origin", resp.Header.Get("Cross-Origin-Opener-Policy"))
	assert.NotEmpty(t, resp.Header.Get("Strict-Transport-Security"), "HSTS header must be set")
	assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'self'")
	assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'")
}

// writeAuditLog writes entries as JSONL to path for handler tests.
func writeAuditLog(t *testing.T, path string, entries []audit.Entry) {
	t.Helper()
	f, err := os.Create(path) //nolint:gosec // test temp file
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	for _, e := range entries {
		require.NoError(t, enc.Encode(e))
	}
}

// TestProjectRigRowHonestEnums asserts the exported RigStatusRow → internal
// rigRow projection maps honest tri-state enums to honest CSS classes and never
// fabricates an all-clear (WR-05): "unknown" reachability stays dot-unknown, an
// absent lock/cert stays N/A.
func TestProjectRigRowHonestEnums(t *testing.T) {
	cases := []struct {
		name        string
		in          RigStatusRow
		wantStatus  string
		wantLabel   string
		wantLock    string
		wantLockCls string
		wantCert    string
		wantCertCls string
	}{
		{
			name:       "online locked healthy cert",
			in:         RigStatusRow{Reachable: "online", Lock: "locked", HasCert: true, CertDays: 90},
			wantStatus: "dot-online", wantLabel: "online", wantLock: "Locked", wantLockCls: "lock-ok",
			wantCert: "90d", wantCertCls: "",
		},
		{
			name:       "unknown reachability stays unknown (no fabricated online)",
			in:         RigStatusRow{Reachable: "unknown", Lock: ""},
			wantStatus: "dot-unknown", wantLabel: "unknown", wantLock: "N/A", wantLockCls: "lock-na",
			wantCert: "N/A", wantCertCls: "",
		},
		{
			name:       "offline + expiring cert warns",
			in:         RigStatusRow{Reachable: "offline", Lock: "unlocked", HasCert: true, CertDays: 10},
			wantStatus: "dot-offline", wantLabel: "offline", wantLock: "Unlocked", wantLockCls: "lock-warn",
			wantCert: "10d", wantCertCls: "cert-warn",
		},
		{
			name:       "near-expiry cert is fatal",
			in:         RigStatusRow{Reachable: "online", HasCert: true, CertDays: 3},
			wantStatus: "dot-online", wantLabel: "online", wantLock: "N/A", wantLockCls: "lock-na",
			wantCert: "3d", wantCertCls: "cert-fatal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := projectRigRow(tc.in)
			assert.Equal(t, tc.wantStatus, got.StatusClass)
			assert.Equal(t, tc.wantLabel, got.StatusLabel)
			assert.Equal(t, tc.wantLock, got.LockStatus)
			assert.Equal(t, tc.wantLockCls, got.LockClass)
			assert.Equal(t, tc.wantCert, got.CertDays)
			assert.Equal(t, tc.wantCertCls, got.CertClass)
		})
	}
}

// TestStatusFuncAdapterRendersRealRows asserts the exported StatusFunc seam
// (the daemon entrypoint's injection point) flows through to the rendered
// fleet-status view, so a non-nil provider yields REAL rows — the B3 wiring.
func TestStatusFuncAdapterRendersRealRows(t *testing.T) {
	fn := StatusFunc(func(_ context.Context) (int, int, []RigStatusRow) {
		return 1, 2, []RigStatusRow{
			{Name: "laptop", Reachable: "online", Lock: "locked", LastSeen: "now", IsLocalRig: true},
			{Name: "workstation", Reachable: "unknown", Lock: ""},
		}
	})
	h, err := NewHandlers(HandlerDeps{
		Status:       statusFuncAdapter{fn: fn},
		Doctor:       stubDoctorProvider{},
		Ring:         NewNotifyRingBuffer(),
		AuditLogPath: "",
		RigHostname:  "laptop",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.handleRoot(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "laptop", "real local rig name must render")
	assert.Contains(t, body, "workstation", "real remote rig name must render")
	assert.Contains(t, body, "dot-unknown", "unprobed rig must render the honest unknown dot, not a fabricated online (WR-05)")
}

// TestDoctorFuncAdapterRendersFinding asserts the exported DoctorFunc seam
// renders a real finding in the /doctor view when the provider is non-nil.
func TestDoctorFuncAdapterRendersFinding(t *testing.T) {
	fn := DoctorFunc(func(_ context.Context) []modules.Finding {
		return []modules.Finding{
			{Module: "ssh", Check: "sec-ssh-permitroot", Severity: modules.SeverityFatal, Message: "PermitRootLogin is yes"},
		}
	})
	h, err := NewHandlers(HandlerDeps{
		Status:       stubStatusProvider{},
		Doctor:       doctorFuncAdapter{fn: fn},
		Ring:         NewNotifyRingBuffer(),
		AuditLogPath: "",
		RigHostname:  "laptop",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/doctor", nil)
	req.RemoteAddr = "100.64.0.5:40000"
	rec := httptest.NewRecorder()
	h.handleDoctor(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "sec-ssh-permitroot", "doctor view must render the real finding check name")
	assert.Contains(t, body, "FATAL", "doctor view must render the finding's FATAL badge")
}

// compile-time assertion that the module satisfies the Module interface.
var _ modules.Module = (*Module)(nil)
