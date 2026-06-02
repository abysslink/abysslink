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
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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
	sw, err := newSafewebServer(mux)
	require.NoError(t, err)

	srv := httptest.NewServer(sw)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
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

func TestNotifyFormCSRFToken(t *testing.T) {
	// With allow_notify enabled, the notify view must emit the safeweb CSRF
	// token field, and the end-to-end POST must require it (WR-02, WEB-05).
	h, err := NewHandlers(HandlerDeps{
		Status: stubStatusProvider{}, Doctor: stubDoctorProvider{},
		Ring: NewNotifyRingBuffer(), AuditLogPath: "", RigHostname: "rig-a",
		AllowNotify: true,
	})
	require.NoError(t, err)
	mux := http.NewServeMux()
	h.Register(mux)
	sw, err := newSafewebServer(mux)
	require.NoError(t, err)
	// safeweb sets a Secure CSRF cookie (SecureContext: true), so the positive
	// path must run over TLS or the cookie jar would never replay the cookie on
	// POST. httptest.NewTLSServer + its trusting client provides that.
	srv := httptest.NewTLSServer(sw)
	defer srv.Close()

	// A cookie jar is required so the CSRF cookie set on GET is replayed on POST.
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := srv.Client()
	client.Jar = jar

	resp, err := client.Get(srv.URL + "/notify")
	require.NoError(t, err)
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	body := string(bodyBytes)

	assert.Contains(t, body, `name="gorilla.csrf.Token"`, "notify form must include the safeweb CSRF token field (WR-02)")

	// Extract the masked token value emitted by safeweb.CSRFTemplateField.
	token := extractCSRFToken(t, body)
	require.NotEmpty(t, token, "CSRF token value must be present in the form")

	// postForm issues a POST with the values, a form content-type, and a Referer
	// matching the origin (gorilla/csrf requires a matching Referer over HTTPS).
	postForm := func(values url.Values) *http.Response {
		req, rerr := http.NewRequest(http.MethodPost, srv.URL+"/notify", strings.NewReader(values.Encode()))
		require.NoError(t, rerr)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", srv.URL+"/notify")
		out, derr := client.Do(req)
		require.NoError(t, derr)
		return out
	}

	// POST without the token must be rejected by the CSRF gate.
	noTok := postForm(url.Values{"title": {"hello"}})
	_ = noTok.Body.Close()
	assert.Equal(t, http.StatusForbidden, noTok.StatusCode, "POST without CSRF token must be 403 (WEB-05)")

	// POST WITH the token must pass the CSRF gate and reach the handler (501).
	withTok := postForm(url.Values{"title": {"hello"}, "gorilla.csrf.Token": {token}})
	_ = withTok.Body.Close()
	assert.Equal(t, http.StatusNotImplemented, withTok.StatusCode,
		"POST with a valid CSRF token must reach handleNotifyPost (501 scaffold)")
}

// extractCSRFToken pulls the masked token value out of the hidden input that
// safeweb.CSRFTemplateField emits (<input ... name="gorilla.csrf.Token" value="...">).
func extractCSRFToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="gorilla.csrf.Token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
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

// compile-time assertion that the module satisfies the Module interface.
var _ modules.Module = (*Module)(nil)

// safeweb.Server must implement http.Handler (used as the inner handler).
var _ http.Handler = (*safeweb.Server)(nil)
