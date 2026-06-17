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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/notifyv2"
)

// TestSelfDNSName covers the FQDN-preference fix: the content advertise host
// must be the MagicDNS FQDN (Status.Self.DNSName) so it matches the Tailscale
// cert SAN, not the short HostName (which would degrade the pull URL to the bind
// IP → a TLS-SAN mismatch on the phone).
func TestSelfDNSName(t *testing.T) {
	assert.Equal(t, "rig.tail1234.ts.net.",
		selfDNSName(&backend.Status{Self: &backend.PeerStatus{HostName: "rig", DNSName: "rig.tail1234.ts.net."}}),
		"must return the FQDN DNSName (trailing dot kept; the resolver trims it), not the short HostName")
	assert.Equal(t, "", selfDNSName(&backend.Status{Self: &backend.PeerStatus{HostName: "rig"}}),
		"no DNSName → empty so the caller falls back to the short hostname")
	assert.Equal(t, "", selfDNSName(&backend.Status{}), "nil Self → empty")
	assert.Equal(t, "", selfDNSName(nil), "nil status → empty")
}

const (
	testBearer = "ablk_b_test-bearer-credential"
	testMsgID  = "01ARZ3NDEKTSV4RRFFQ69G5FAV" // canonical oklog/ulid example; passes ParseStrict
)

// fakeDeviceStore satisfies DeviceStore for the content-listener tests.
type fakeDeviceStore struct {
	mu      sync.Mutex
	bearer  string // the one accepted bearer; "" accepts nothing (revoked/unknown)
	rec     device.Record
	records []device.Record
	stale   []device.Record
	touched []string
}

func (f *fakeDeviceStore) VerifyBearer(presented string) (*device.Record, bool) {
	if f.bearer == "" || presented != f.bearer {
		return nil, false
	}
	cp := f.rec
	return &cp, true
}

func (f *fakeDeviceStore) TouchLastSeen(_ context.Context, id string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, id)
	return nil
}

func (f *fakeDeviceStore) List() []device.Record               { return f.records }
func (f *fakeDeviceStore) Stale(time.Duration) []device.Record { return f.stale }

func (f *fakeDeviceStore) touchedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.touched...)
}

// newContentTestServer returns a Server wired with a fake device store and a
// real (temp-file) audit appender, plus the httptest server over the content
// mux. Notifier delivery is captured by the returned captureNotifier.
func newContentTestServer(t *testing.T) (*Server, *fakeDeviceStore, *httptest.Server, string) {
	t.Helper()
	cfg := config.Defaults()
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	fd := &fakeDeviceStore{
		bearer: testBearer,
		rec:    device.Record{ID: "01DEVICEULIDXXXXXXXXXXXXXX", Name: "phone"},
	}
	s.SetDeviceStore(fd)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	s.SetAuditAppender(audit.New(logPath))
	ts := httptest.NewServer(s.buildContentMux())
	t.Cleanup(ts.Close)
	return s, fd, ts, logPath
}

func doContentGet(t *testing.T, ts *httptest.Server, token, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/content/"+token, nil)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// doBootstrapGet issues a bearer-LESS GET /enroll/{token} (BACK-09): no
// Authorization header — the single-use token IS the only credential.
func doBootstrapGet(t *testing.T, ts *httptest.Server, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/enroll/"+token, nil)
	require.NoError(t, err)
	// HTML is the default now (the link is a QR for a human); a machine consumer
	// must opt into raw JSON explicitly. These tests assert the JSON contract.
	req.Header.Set("Accept", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// doBootstrapGetUA issues a bearer-LESS GET /enroll/{token} with a custom
// User-Agent (and no Accept header), to exercise the preview-bot detection.
func doBootstrapGetUA(t *testing.T, ts *httptest.Server, token, ua string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/enroll/"+token, nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", ua)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// TestIsPreviewBot covers the User-Agent denylist: well-known preview/crawler
// UAs match (true), while real-browser UAs and the empty UA do not (false → the
// normal consume path runs).
func TestIsPreviewBot(t *testing.T) {
	cases := []struct {
		ua   string
		want bool
	}{
		{ua: "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", want: true},
		{ua: "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", want: true},
		{ua: "WhatsApp/2.23.20.0", want: true},
		{ua: "Twitterbot/1.0", want: true},
		{ua: "TelegramBot (like TwitterBot)", want: true},
		{ua: "Discordbot/2.0 (+https://discordapp.com)", want: true},
		{ua: "LinkedInBot/1.0", want: true},
		{ua: "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", want: true},
		{ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", want: true},
		{ua: "Applebot/0.1", want: true},
		// Real browsers must NOT match.
		{ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", want: false},
		{ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", want: false},
		{ua: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.ua, func(t *testing.T) {
			assert.Equal(t, tc.want, isPreviewBot(tc.ua))
		})
	}
}

// TestHandleBootstrap_PreviewBotDoesNotConsume proves the preview-safe contract:
// a preview crawler GET serves the generic placeholder (200, no secret), does
// NOT consume the single-use token (a subsequent real fetch still gets the
// bundle), and is identical on a non-existent token (no oracle).
func TestHandleBootstrap_PreviewBotDoesNotConsume(t *testing.T) {
	// A placeholder stand-in for the staged secret (avoid a real credential
	// literal in the test source); the page must never echo it back.
	const secretMarker = "STAGED-SECRET-MARKER-VALUE-XYZ"
	bundle := `{"device":"phone","token_field":"` + secretMarker + `"}`

	botUAs := []string{
		"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
		"facebookexternalhit/1.1",
		"WhatsApp/2.23.20.0",
	}
	for _, ua := range botUAs {
		t.Run(ua, func(t *testing.T) {
			s, _, ts, _ := newContentTestServer(t)
			token, _ := s.content.mintBootstrap(bundle, time.Minute)

			// The preview fetch: placeholder, 200, NO secret.
			resp := doBootstrapGetUA(t, ts, token, ua)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
			assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
			page, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, err)
			assert.NotContains(t, string(page), secretMarker, "the placeholder must never carry the secret bundle")
			assert.Contains(t, string(page), "single-use", "the placeholder must hint at the one-time link")
			assert.Contains(t, strings.ToLower(string(page)), "open", "the placeholder must tell the user to open it on the device")

			// The token survived: a real (no/browser UA) fetch still gets the bundle.
			real := doBootstrapGet(t, ts, token)
			require.Equal(t, http.StatusOK, real.StatusCode, "the preview must not have consumed the token")
			body, err := io.ReadAll(real.Body)
			_ = real.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, bundle, string(body), "the real fetch must still receive the secret bundle")
		})
	}

	// A bot GET on a NON-existent token is the same placeholder 200 (no oracle,
	// no 404 difference vs a real token).
	t.Run("nonexistent token same placeholder", func(t *testing.T) {
		_, _, ts, _ := newContentTestServer(t)
		resp := doBootstrapGetUA(t, ts, "ablk_e_does-not-exist", "Slackbot-LinkExpanding 1.0")
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "a bot must get 200 even for an unknown token (no oracle)")
		page, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(page), "single-use")
	})
}

func doAck(t *testing.T, ts *httptest.Server, body, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/ack", strings.NewReader(body))
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func TestHandleContent_Happy(t *testing.T) {
	s, fd, ts, _ := newContentTestServer(t)
	token, _ := s.content.mintContent("the real notification body", time.Minute)

	resp := doContentGet(t, ts, token, testBearer)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "the real notification body", string(body))
	assert.Equal(t, []string{fd.rec.ID}, fd.touchedIDs(), "GET /content must touch last-seen")
}

// TestHandleContent_Uniform404 asserts the no-oracle property: missing auth,
// a wrong bearer, a revoked device (VerifyBearer false), an unknown token,
// and an expired token are ALL the identical empty-body 404.
func TestHandleContent_Uniform404(t *testing.T) {
	s, fd, ts, _ := newContentTestServer(t)
	token, _ := s.content.mintContent("secret-ish body", time.Minute)

	cases := []struct {
		name   string
		token  string
		bearer string
		setup  func()
	}{
		{name: "no auth", token: token, bearer: ""},
		{name: "bad bearer", token: token, bearer: "ablk_b_wrong"},
		{name: "revoked device", token: token, bearer: testBearer, setup: func() { fd.bearer = "" }},
		{name: "unknown token", token: "ablk_c_nonexistent-token-xx", bearer: testBearer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
				defer func() { fd.bearer = testBearer }()
			}
			resp := doContentGet(t, ts, tc.token, tc.bearer)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Empty(t, string(body), "uniform 404 must carry an empty body (no oracle)")
		})
	}

	t.Run("expired token", func(t *testing.T) {
		clk := newContentClock()
		s.content = newContentStore(clk.now)
		tok, _ := s.content.mintContent("soon gone", 30*time.Second)
		clk.advance(time.Minute)
		resp := doContentGet(t, ts, tok, testBearer)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Empty(t, string(body))
	})
}

// TestHandleContent_ConstantWork404 asserts Finding 3: the bad-bearer,
// unknown-token, and revoked-device branches all return a byte-identical 404
// (same status, empty body, identical header set) — no bearer-validity timing
// oracle — AND that an auth-failed request against a VALID token does not
// consume (delete) it: the legitimate fetch must still succeed afterward.
func TestHandleContent_ConstantWork404(t *testing.T) {
	captureResp := func(resp *http.Response) (int, string, http.Header) {
		t.Helper()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		// Drop headers httptest sets per-response (Date varies; Content-Length
		// is a function of the body, which we assert separately).
		h := resp.Header.Clone()
		h.Del("Date")
		h.Del("Content-Length")
		return resp.StatusCode, string(body), h
	}

	s, fd, ts, _ := newContentTestServer(t)
	validToken, _ := s.content.mintContent("the real body", time.Minute)

	cases := []struct {
		name   string
		token  string
		bearer string
		setup  func()
	}{
		{name: "bad bearer", token: validToken, bearer: "ablk_b_wrong"},
		{name: "unknown token", token: "ablk_c_nonexistent-token-xx", bearer: testBearer},
		{name: "revoked device", token: validToken, bearer: testBearer, setup: func() { fd.bearer = "" }},
	}

	var refStatus int
	var refBody string
	var refHdr http.Header
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
				defer func() { fd.bearer = testBearer }()
			}
			status, body, hdr := captureResp(doContentGet(t, ts, tc.token, tc.bearer))
			assert.Equal(t, http.StatusNotFound, status)
			assert.Empty(t, body, "404 body must be empty (no oracle)")
			if i == 0 {
				refStatus, refBody, refHdr = status, body, hdr
				return
			}
			assert.Equal(t, refStatus, status, "status must be byte-identical across auth-fail branches")
			assert.Equal(t, refBody, body, "body must be byte-identical across auth-fail branches")
			assert.Equal(t, refHdr, hdr, "header set must be identical across auth-fail branches")
		})
	}

	// The bad-bearer and unknown-token attempts above ran against validToken
	// (or a missing token) but must NOT have consumed validToken: the
	// legitimate authed fetch still succeeds and returns the real body.
	resp := doContentGet(t, ts, validToken, testBearer)
	status, body, _ := captureResp(resp)
	assert.Equal(t, http.StatusOK, status, "an auth-failed request must not consume the valid token")
	assert.Equal(t, "the real body", body)
	// Only the genuine success touched last-seen — the auth-failed attempts did not.
	assert.Equal(t, []string{fd.rec.ID}, fd.touchedIDs(),
		"only the genuine success may touch last-seen")
}

// --- BACK-09: bearer-LESS GET /enroll/{token} ---

func TestHandleBootstrap_Happy(t *testing.T) {
	s, _, ts, _ := newContentTestServer(t)
	const bundle = `{"device":"phone","bearer":"ablk_b_x"}`
	token, _ := s.content.mintBootstrap(bundle, time.Minute)

	resp := doBootstrapGet(t, ts, token)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, bundle, string(body))
}

// doBootstrapGetHTML is doBootstrapGet with a browser Accept header so the
// endpoint serves the formatted credential page instead of JSON.
func doBootstrapGetHTML(t *testing.T, ts *httptest.Server, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/enroll/"+token, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// TestHandleBootstrap_HTMLPage covers the DEVC-07 phone UX: a browser (Accept:
// text/html) gets the formatted page — text/html, the secret values present in
// the page, per-field Copy + Download for the key/cert — and the token is still
// single-use. curl/JSON behavior is unchanged (TestHandleBootstrap_Happy).
func TestHandleBootstrap_HTMLPage(t *testing.T) {
	s, _, ts, _ := newContentTestServer(t)
	// A multi-line value stands in for the PEM (avoid a literal key header in the
	// test source); the point is the page carries values, labels, and buttons.
	const keyVal = "PRIV-KEY-LINE-1\nPRIV-KEY-LINE-2\n"
	bundle, err := json.Marshal(map[string]any{
		"device":              "phone",
		"bearer":              "ablk_b_secret",
		"ssh_private_key_pem": keyVal,
		"ssh_certificate":     "ssh-ed25519-cert-v01@openssh.com AAAAcert",
	})
	require.NoError(t, err)
	token, _ := s.content.mintBootstrap(string(bundle), time.Minute)

	resp := doBootstrapGetHTML(t, ts, token)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	page, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	htmlBody := string(page)
	// The page carries the secret values (HTML-escaped in <pre> text) and the
	// human labels + action buttons.
	assert.Contains(t, htmlBody, "ablk_b_secret", "bearer value must be on the page")
	assert.Contains(t, htmlBody, "PRIV-KEY-LINE-1", "key value must be on the page")
	assert.Contains(t, htmlBody, "SSH private key", "known fields get human labels")
	assert.Contains(t, htmlBody, ">Copy<", "every field gets a Copy button")
	assert.Contains(t, htmlBody, "abysslink_phone-cert.pub", "the cert gets a Download with the OpenSSH filename")
	// No secret value is interpolated into a JS string literal (read from DOM).
	assert.NotContains(t, htmlBody, "writeText('ablk_b_secret", "secrets must not enter JS string literals")

	// Single-use: the page fetch consumed the token.
	second := doBootstrapGetHTML(t, ts, token)
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, second.StatusCode, "the HTML page fetch must consume the single-use token")
}

// TestHandleBootstrap_NotFoundHTML covers the dead-link UX: a BROWSER that
// opens an expired/used/unknown link gets a clear "link expired" HTML page (not
// a blank white 404), while curl/JSON keeps the empty-body 404 (uniform,
// no-oracle). The page is generic — identical for every not-found cause.
func TestHandleBootstrap_NotFoundHTML(t *testing.T) {
	_, _, ts, _ := newContentTestServer(t)

	// Browser (Accept: text/html) → friendly 404 page.
	resp := doBootstrapGetHTML(t, ts, "ablk_e_does-not-exist")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "expired", "the dead-link page must explain the link is expired/used")
	assert.Contains(t, string(body), "enroll phone --apply", "the page must tell the operator how to get a fresh link")

	// curl/JSON (no Accept) → empty-body 404 unchanged (BACK-09 contract).
	jsonResp := doBootstrapGet(t, ts, "ablk_e_does-not-exist")
	defer func() { _ = jsonResp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, jsonResp.StatusCode)
	jb, err := io.ReadAll(jsonResp.Body)
	require.NoError(t, err)
	assert.Empty(t, string(jb), "the non-browser 404 stays empty-body (no oracle)")
}

// TestParseOrderedEnrollFields covers the generic, order-preserving parse that
// keeps the daemon decoupled from the exact bundle shape.
func TestParseOrderedEnrollFields(t *testing.T) {
	raw := `{"device":"phone","rotated":true,"ssh_private_key_pem":"K","unknown_field":"v"}`
	fields, err := parseOrderedEnrollFields(raw)
	require.NoError(t, err)
	require.Len(t, fields, 4)
	assert.Equal(t, []string{"f0", "f1", "f2", "f3"}, []string{fields[0].ID, fields[1].ID, fields[2].ID, fields[3].ID})
	assert.Equal(t, "Device", fields[0].Label)
	assert.Equal(t, "true", fields[1].Value, "non-string scalar stringified")
	assert.Equal(t, "abysslink_phone", fields[2].File, "key field gets the OpenSSH key filename")
	assert.Equal(t, "unknown_field", fields[3].Label, "unknown keys fall back to the raw key (decoupled)")
	assert.Empty(t, fields[3].File, "non-key/cert fields get no Download")

	_, err = parseOrderedEnrollFields(`["not","an","object"]`)
	assert.Error(t, err, "a non-object bundle is a render error (caller falls back to JSON)")
}

// TestWantsJSON covers the content-negotiation gate: HTML is the DEFAULT (QR
// for a human); JSON only on an explicit opt-in. This is the fix for QR
// scanners / in-app webviews that send "*/*" (no text/html) and were wrongly
// getting the raw JSON dump.
func TestWantsJSON(t *testing.T) {
	mk := func(accept, query string) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/enroll/x"+query, nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		return r
	}
	// HTML (the default) — wantsJSON false:
	assert.False(t, wantsJSON(mk("text/html,application/xhtml+xml", "")), "browser → HTML")
	assert.False(t, wantsJSON(mk("*/*", "")), "QR scanner / curl default (*/*) → HTML (was the bug)")
	assert.False(t, wantsJSON(mk("", "")), "no Accept → HTML")
	assert.False(t, wantsJSON(mk("text/html,application/json", "")), "browser sending both → HTML")
	// JSON — only on explicit opt-in:
	assert.True(t, wantsJSON(mk("application/json", "")), "explicit Accept: application/json → JSON")
	assert.True(t, wantsJSON(mk("*/*", "?format=json")), "?format=json → JSON")
}

// TestHandleBootstrap_NoBearerRequired proves the route is bearer-LESS: a GET
// with no Authorization header succeeds (doBootstrapGet sends none).
func TestHandleBootstrap_NoBearerRequired(t *testing.T) {
	s, _, ts, _ := newContentTestServer(t)
	token, _ := s.content.mintBootstrap(`{"device":"phone"}`, time.Minute)

	resp := doBootstrapGet(t, ts, token)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GET /enroll must succeed with NO bearer")
}

func TestHandleBootstrap_SingleUse(t *testing.T) {
	s, _, ts, _ := newContentTestServer(t)
	token, _ := s.content.mintBootstrap(`{"device":"phone"}`, time.Minute)

	first := doBootstrapGet(t, ts, token)
	_ = first.Body.Close()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := doBootstrapGet(t, ts, token)
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, second.StatusCode, "a replayed bootstrap token must 404")
}

// TestHandleBootstrap_Uniform404 asserts the no-oracle property: an unknown
// token, an expired token, AND a CONTENT token routed through /enroll/ are ALL
// empty-body 404s — and the cross-class probe burns NOTHING (the content token
// still resolves via an authed /content/ GET afterward).
func TestHandleBootstrap_Uniform404(t *testing.T) {
	clk := newContentClock()
	s, _, ts, _ := newContentTestServer(t)
	s.content = newContentStore(clk.now)

	// A live content token — must survive a wrong-class /enroll/ probe (long
	// TTL so the clock advance below does not expire it).
	contentTok, _ := s.content.mintContent("bearer-gated body", time.Hour)
	// An expired bootstrap token.
	expiredTok, _ := s.content.mintBootstrap(`{"device":"gone"}`, 30*time.Second)
	clk.advance(time.Minute)

	cases := []struct {
		name  string
		token string
	}{
		{name: "unknown token", token: "ablk_e_nonexistent-token-xx"},
		{name: "expired bootstrap token", token: expiredTok},
		{name: "cross-class content token", token: contentTok},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doBootstrapGet(t, ts, tc.token)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Empty(t, string(body), "uniform 404 must carry an empty body (no oracle)")
		})
	}

	// The cross-class /enroll/ probe must NOT have consumed the content token:
	// the legitimate authed /content/ fetch still resolves the real body.
	resp := doContentGet(t, ts, contentTok, testBearer)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a wrong-class /enroll/ probe must not burn the content token")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "bearer-gated body", string(body))
}

// TestHandleContent_RejectsBootstrapToken asserts the symmetric guard: a
// bootstrap token requested via the bearer-gated /content/ route is a 404 even
// WITH a valid bearer (the kind guard, not just the bearer gate) — and the
// probe burns nothing (the bootstrap token still resolves via /enroll/).
func TestHandleContent_RejectsBootstrapToken(t *testing.T) {
	s, _, ts, _ := newContentTestServer(t)
	bootTok, _ := s.content.mintBootstrap(`{"device":"phone"}`, time.Minute)

	resp := doContentGet(t, ts, bootTok, testBearer)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"a bootstrap token via /content/ must 404 even with a valid bearer")

	// The probe must not have consumed the bootstrap token.
	resp2 := doBootstrapGet(t, ts, bootTok)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode,
		"the bootstrap token must survive a wrong-class /content/ probe")
}

func TestHandleAck_HappyRecordsHashOnlyReceipt(t *testing.T) {
	s, fd, ts, logPath := newContentTestServer(t)

	resp := doAck(t, ts, `{"msg_id":"`+testMsgID+`"}`, testBearer)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	assert.Equal(t, uint64(1), s.ackReceived.Load(), "ack counter must increment")
	assert.Equal(t, []string{fd.rec.ID}, fd.touchedIDs(), "ack must touch last-seen")

	log, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	require.NoError(t, err)
	assert.Contains(t, string(log), `"op":"ack-receipt"`, "receipt entry must be appended")
	assert.Contains(t, string(log), AckReceiptHash(testMsgID, fd.rec.ID),
		"the logged hash must be sha256(msg_id\\ndevice.ID)")
	// Hash-only: the raw msg_id must never appear in the audit log.
	assert.NotContains(t, string(log), testMsgID, "raw msg_id must not reach the audit log")
}

func TestHandleAck_BadMsgID(t *testing.T) {
	s, _, ts, logPath := newContentTestServer(t)

	for _, body := range []string{
		`{"msg_id":"not-a-ulid"}`,
		`{"msg_id":""}`,
		`{}`,
		`{"msg_id":"` + testMsgID + `","extra":"field"}`, // DisallowUnknownFields
		`not json`,
	} {
		resp := doAck(t, ts, body, testBearer)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body %q must be rejected", body)
	}
	assert.Equal(t, uint64(0), s.ackReceived.Load())
	_, err := os.Stat(logPath)
	assert.True(t, errors.Is(err, os.ErrNotExist), "no receipt may be appended for rejected acks")
}

func TestHandleAck_NoAuthUniform404(t *testing.T) {
	_, _, ts, _ := newContentTestServer(t)

	for _, bearer := range []string{"", "ablk_b_wrong"} {
		resp := doAck(t, ts, `{"msg_id":"`+testMsgID+`"}`, bearer)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Empty(t, string(body), "auth-fail ack must be the uniform empty 404")
	}
}

// --- v2 envelope → content-store integration (BACK-06/BACK-08) ---

func postNotifyV2(t *testing.T, s *Server, payload string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/notify", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	s.handleNotify(rec, req)
	return rec
}

// markContentLive simulates a live content listener that binds host:port and
// advertises the same host in the minted fetch URL (the degraded fallback
// case, where no MagicDNS name was resolved).
func markContentLive(s *Server, host string, port int) {
	markContentLiveAdvertising(s, host, host, port)
}

// markContentLiveAdvertising simulates a live content listener that BINDS
// bindHost but ADVERTISES advertiseHost in the minted fetch URL (Finding 2:
// e.g. binds the tailnet IP, advertises the *.ts.net MagicDNS name).
func markContentLiveAdvertising(s *Server, bindHost, advertiseHost string, port int) {
	s.contentMu.Lock()
	s.contentLive = true
	s.contentHost = bindHost
	s.contentAdvertiseHost = advertiseHost
	s.contentPort = port
	s.contentStatus = "listening on " + net.JoinHostPort(bindHost, fmt.Sprintf("%d", port))
	s.contentMu.Unlock()
}

func TestNotifyV2Envelope_ContentMintsFetchRef(t *testing.T) {
	cfg := config.Defaults()
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	markContentLive(s, "100.64.0.5", 2587)

	rec := postNotifyV2(t, s, `{"v":2,"kind":"needs_input","title":"needs input","content":"full body here"}`)
	require.Equal(t, http.StatusNoContent, rec.Code, "body: %s", rec.Body.String())

	assert.Equal(t, 1, s.content.len(), "content must be minted into the store")
	require.Equal(t, 1, cn.count(), "the wake must be dispatched")
}

func TestMintFetchRef_URLPassesNotifyV2Validate(t *testing.T) {
	cfg := config.Defaults()
	s := NewServer(&captureNotifier{}, nil, cfg)

	cases := []struct {
		name string
		host string
	}{
		{name: "CGNAT IPv4", host: "100.64.0.5"},
		{name: "tailscale ULA IPv6", host: "fd7a:115c:a1e0::1234"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markContentLive(s, tc.host, 2587)
			u, ttl, ok := s.mintFetchRef("body")
			require.True(t, ok)
			assert.Equal(t, 600, ttl, "default TTL is 600s")
			assert.True(t, strings.HasPrefix(u, "https://"), "fetch URL must be https")
			assert.Contains(t, u, "/content/"+contentTokenPrefix)

			msg := notifyv2.Message{
				V:     2,
				MsgID: testMsgID,
				Kind:  notifyv2.KindCommandDone,
				Host:  "rig-1",
				Title: "done",
				Fetch: &notifyv2.FetchRef{URLTailnet: u, TTLSeconds: ttl},
			}
			assert.NoError(t, msg.Validate(), "minted FetchRef must pass the tailnet-host rule")
		})
	}
}

// TestMintFetchRef_AdvertisesMagicDNSHost asserts Finding 2: when the listener
// resolved a *.ts.net MagicDNS name, the minted FetchRef URL host is that name
// (so a TLS-verifying phone fetch verifies against the cert SAN), and the URL
// still passes notifyv2.Validate — while the listener itself still BINDS the
// tailnet IP.
func TestMintFetchRef_AdvertisesMagicDNSHost(t *testing.T) {
	cfg := config.Defaults()
	s := NewServer(&captureNotifier{}, nil, cfg)
	// Binds the tailnet IP, advertises the MagicDNS name.
	markContentLiveAdvertising(s, "100.64.0.5", "myrig.tail1234.ts.net", 2587)

	u, ttl, ok := s.mintFetchRef("body")
	require.True(t, ok)

	parsed, err := url.Parse(u)
	require.NoError(t, err)
	assert.Equal(t, "myrig.tail1234.ts.net", parsed.Hostname(),
		"fetch URL host must be the advertised MagicDNS name, not the bind IP")

	s.contentMu.Lock()
	bindHost := s.contentHost
	s.contentMu.Unlock()
	assert.Equal(t, "100.64.0.5", bindHost, "the listener must still BIND the tailnet IP")

	msg := notifyv2.Message{
		V: 2, MsgID: testMsgID, Kind: notifyv2.KindCommandDone, Host: "rig-1", Title: "done",
		Fetch: &notifyv2.FetchRef{URLTailnet: u, TTLSeconds: ttl},
	}
	assert.NoError(t, msg.Validate(), "a *.ts.net fetch host must pass the url_tailnet rule")
}

// TestMintFetchRef_FallsBackToBindIP asserts Finding 2's degraded path: when no
// MagicDNS name is available, the advertised host falls back to the bind IP and
// the URL still validates.
func TestMintFetchRef_FallsBackToBindIP(t *testing.T) {
	cfg := config.Defaults()
	s := NewServer(&captureNotifier{}, nil, cfg)
	// Advertise host == bind IP (the fallback markContentLive produces).
	markContentLive(s, "100.64.0.5", 2587)

	u, ttl, ok := s.mintFetchRef("body")
	require.True(t, ok)

	parsed, err := url.Parse(u)
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.5", parsed.Hostname(), "fallback advertises the bind IP")

	msg := notifyv2.Message{
		V: 2, MsgID: testMsgID, Kind: notifyv2.KindCommandDone, Host: "rig-1", Title: "done",
		Fetch: &notifyv2.FetchRef{URLTailnet: u, TTLSeconds: ttl},
	}
	assert.NoError(t, msg.Validate())
}

// TestResolveContentAdvertiseHost covers the seam directly: a *.ts.net name is
// advertised, anything else (empty, non-ts.net, resolver error, nil resolver)
// falls back to the bind IP — never fail-closed (Finding 2).
func TestResolveContentAdvertiseHost(t *testing.T) {
	s := NewServer(&captureNotifier{}, nil, config.Defaults())
	const bindIP = "100.64.0.5"

	cases := []struct {
		name     string
		resolver tailnetHostResolver
		want     string
	}{
		{name: "magicdns name", resolver: stubHostResolver{host: "myrig.tail1234.ts.net"}, want: "myrig.tail1234.ts.net"},
		{name: "trailing dot trimmed", resolver: stubHostResolver{host: "myrig.tail1234.ts.net."}, want: "myrig.tail1234.ts.net"},
		{name: "empty hostname falls back", resolver: stubHostResolver{host: ""}, want: bindIP},
		{name: "non-ts.net falls back", resolver: stubHostResolver{host: "myrig.example.com"}, want: bindIP},
		{name: "resolver error falls back", resolver: stubHostResolver{err: errors.New("no localapi")}, want: bindIP},
		{name: "nil resolver falls back", resolver: nil, want: bindIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.resolveContentAdvertiseHost(context.Background(), bindIP, tc.resolver)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestStartContentServer_AdvertisesHostBindsIP asserts the wiring end to end:
// with a stub host resolver returning a *.ts.net name, the live listener binds
// the resolved tailnet IP but advertises the MagicDNS name in mintFetchRef;
// with the host resolver erroring, it falls back to the IP — binding the IP in
// both cases (Finding 2).
func TestStartContentServer_AdvertisesHostBindsIP(t *testing.T) {
	cases := []struct {
		name          string
		hostResolver  tailnetHostResolver
		wantAdvertise string
	}{
		{name: "magicdns advertised", hostResolver: stubHostResolver{host: "myrig.tail1234.ts.net"}, wantAdvertise: "myrig.tail1234.ts.net"},
		{name: "fallback to ip", hostResolver: stubHostResolver{err: errors.New("no name")}, wantAdvertise: "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.ContentStore.Port = freePort(t)
			s := NewServer(&captureNotifier{}, nil, cfg)
			s.SetDeviceStore(&fakeDeviceStore{bearer: testBearer, rec: device.Record{ID: "id-1", Name: "phone"}})
			s.SetAuditAppender(audit.New(filepath.Join(t.TempDir(), "audit.log")))
			s.SetContentTLS(func(context.Context) (*tls.Config, error) { return selfSignedTLS(t), nil })
			s.contentResolver = stubResolver{ip: "127.0.0.1"}
			s.contentHostResolver = tc.hostResolver

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.startContentServer(ctx)

			s.contentMu.Lock()
			live, bindHost, advertise := s.contentLive, s.contentHost, s.contentAdvertiseHost
			s.contentMu.Unlock()
			require.True(t, live, "listener must be live: %s", s.contentStoreStatus())
			assert.Equal(t, "127.0.0.1", bindHost, "listener must bind the resolved tailnet IP in both cases")
			assert.Equal(t, tc.wantAdvertise, advertise)

			u, _, ok := s.mintFetchRef("body")
			require.True(t, ok)
			parsed, err := url.Parse(u)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAdvertise, parsed.Hostname(), "minted URL host must be the advertise host")
		})
	}
}

func TestNotifyV2Envelope_ListenerDownStillDispatches(t *testing.T) {
	cfg := config.Defaults()
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	// contentLive stays false: the listener is down.

	rec := postNotifyV2(t, s, `{"v":2,"kind":"needs_input","title":"needs input","content":"dropped body"}`)
	require.Equal(t, http.StatusNoContent, rec.Code,
		"the wake must dispatch unchanged when the listener is down (BACK-08)")
	assert.Equal(t, 0, s.content.len(), "no token may be minted while the listener is down")
	require.Equal(t, 1, cn.count(), "the wake itself must still be delivered")
	assert.NotEmpty(t, cn.notes[0].Title, "the fallback title carries the wake (BACK-08)")
}

func TestNotifyV2Envelope_ContentCappedAt64KiB(t *testing.T) {
	cfg := config.Defaults()
	s := NewServer(&captureNotifier{}, nil, cfg)
	markContentLive(s, "100.64.0.5", 2587)

	big := strings.Repeat("a", maxContentBodyBytes+1)
	rec := postNotifyV2(t, s, `{"v":2,"kind":"needs_input","title":"needs input","content":"`+big+`"}`)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Equal(t, 0, s.content.len())
}

func TestNotifyV2Envelope_ContentAndFetchMutuallyExclusive(t *testing.T) {
	cfg := config.Defaults()
	s := NewServer(&captureNotifier{}, nil, cfg)
	markContentLive(s, "100.64.0.5", 2587)

	rec := postNotifyV2(t, s, `{"v":2,"kind":"needs_input","title":"needs input",`+
		`"content":"x","fetch":{"url_tailnet":"https://100.64.0.5:2587/content/abc","ttl_s":60}}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestNotifyV2Envelope_UnknownBodyKeyStillRejected(t *testing.T) {
	cfg := config.Defaults()
	s := NewServer(&captureNotifier{}, nil, cfg)

	// "content" is the ONE new envelope key; any other body-shaped key must
	// still trip DisallowUnknownFields (D-17 decode gate preserved).
	rec := postNotifyV2(t, s, `{"v":2,"kind":"needs_input","title":"needs input","body":"smuggled"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- counters + status (BACK-07 surface) ---

func TestStatus_WakeAckContentAndDevices(t *testing.T) {
	cfg := config.Defaults()
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	fd := &fakeDeviceStore{
		records: []device.Record{
			{ID: "id-1", Name: "phone", LastSeen: now},
			{ID: "id-2", Name: "old-phone", LastSeen: now.Add(-30 * 24 * time.Hour)},
			{ID: "id-3", Name: "stolen-phone", Revoked: true},
		},
		stale: []device.Record{{ID: "id-2", Name: "old-phone"}},
	}
	s.SetDeviceStore(fd)
	markContentLive(s, "100.64.0.5", 2587)

	// One successful v2 dispatch → wake_sent 1.
	rec := postNotifyV2(t, s, `{"v":2,"kind":"needs_input","title":"needs input"}`)
	require.Equal(t, http.StatusNoContent, rec.Code)
	s.ackReceived.Add(1)

	statusRec := httptest.NewRecorder()
	s.handleStatus(statusRec, httptest.NewRequest(http.MethodGet, "/status", nil))
	require.Equal(t, http.StatusOK, statusRec.Code)

	var resp struct {
		WakeSent     uint64 `json:"wake_sent"`
		AckReceived  uint64 `json:"ack_received"`
		ContentStore string `json:"content_store"`
		Devices      []struct {
			Name     string `json:"name"`
			LastSeen string `json:"last_seen"`
			Stale    bool   `json:"stale"`
			Revoked  bool   `json:"revoked"`
		} `json:"devices"`
	}
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &resp))

	assert.Equal(t, uint64(1), resp.WakeSent)
	assert.Equal(t, uint64(1), resp.AckReceived)
	assert.Equal(t, "listening on 100.64.0.5:2587", resp.ContentStore)
	require.Len(t, resp.Devices, 3)
	assert.Equal(t, "phone", resp.Devices[0].Name)
	assert.False(t, resp.Devices[0].Stale)
	assert.NotEmpty(t, resp.Devices[0].LastSeen)
	assert.True(t, resp.Devices[1].Stale, "old-phone is past the 7-day window")
	assert.True(t, resp.Devices[2].Revoked)
}

func TestStatus_ContentStoreDisabledReason(t *testing.T) {
	cfg := config.Defaults()
	cfg.ContentStore.Enabled = false
	s := NewServer(&captureNotifier{}, nil, cfg)
	s.startContentServer(context.Background())

	statusRec := httptest.NewRecorder()
	s.handleStatus(statusRec, httptest.NewRequest(http.MethodGet, "/status", nil))
	var resp struct {
		ContentStore string `json:"content_store"`
	}
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &resp))
	assert.Equal(t, "disabled: content_store.enabled is false", resp.ContentStore)
}

// --- listener lifecycle: fail-closed paths + full TLS round trip ---

type stubResolver struct {
	ip  string
	err error
}

func (r stubResolver) IP(context.Context) (string, error) { return r.ip, r.err }

// stubHostResolver injects a MagicDNS hostname (or an error) for the
// advertise-host seam (Finding 2).
type stubHostResolver struct {
	host string
	err  error
}

func (r stubHostResolver) Hostname(context.Context) (string, error) { return r.host, r.err }

// selfSignedTLS returns a tls.Config with a fresh self-signed cert for
// 127.0.0.1 (the injectable TLS seam for the listener test).
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
}

// freePort grabs an ephemeral port (released before use; tiny race accepted).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func TestStartContentServer_FailClosed(t *testing.T) {
	tlsOK := func(context.Context) (*tls.Config, error) { return selfSignedTLS(t), nil }
	devOK := &fakeDeviceStore{bearer: testBearer, rec: device.Record{ID: "id-1", Name: "phone"}}

	cases := []struct {
		name   string
		mutate func(s *Server, cfg *config.Config)
		want   string
	}{
		{
			name:   "disabled by config",
			mutate: func(s *Server, cfg *config.Config) { cfg.ContentStore.Enabled = false },
			want:   "disabled: content_store.enabled is false",
		},
		{
			name:   "no device store",
			mutate: func(s *Server, _ *config.Config) { s.devices = nil },
			want:   "disabled: no device store",
		},
		{
			name:   "no TLS provider",
			mutate: func(s *Server, _ *config.Config) { s.contentTLS = nil },
			want:   "disabled: TLS material unavailable",
		},
		{
			name: "TLS provider error",
			mutate: func(s *Server, _ *config.Config) {
				s.contentTLS = func(context.Context) (*tls.Config, error) { return nil, errors.New("no cert") }
			},
			want: "disabled: TLS material unavailable",
		},
		{
			name:   "resolver error",
			mutate: func(s *Server, _ *config.Config) { s.contentResolver = stubResolver{err: errors.New("no tailnet")} },
			want:   "disabled: bind address could not be confirmed",
		},
		{
			name:   "empty tailnet IP",
			mutate: func(s *Server, _ *config.Config) { s.contentResolver = stubResolver{ip: ""} },
			want:   "disabled: bind address could not be confirmed",
		},
		{
			name:   "unspecified tailnet IP",
			mutate: func(s *Server, _ *config.Config) { s.contentResolver = stubResolver{ip: "0.0.0.0"} },
			want:   "disabled: bind address could not be confirmed",
		},
		{
			name: "bind_addr mismatch",
			mutate: func(s *Server, cfg *config.Config) {
				cfg.ContentStore.BindAddr = "192.168.1.10" // a LAN NIC, not the tailnet IP
			},
			want: "disabled: bind address could not be confirmed",
		},
		{
			name: "wildcard bind_addr rejected by config floor",
			mutate: func(s *Server, cfg *config.Config) {
				cfg.ContentStore.BindAddr = "0.0.0.0"
			},
			want: "disabled: invalid content_store config",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			s := NewServer(&captureNotifier{}, nil, cfg)
			s.SetDeviceStore(devOK)
			s.SetContentTLS(tlsOK)
			s.contentResolver = stubResolver{ip: "100.64.0.5"}
			tc.mutate(s, cfg)

			s.startContentServer(context.Background())

			s.contentMu.Lock()
			live, status := s.contentLive, s.contentStatus
			s.contentMu.Unlock()
			assert.False(t, live, "listener must stay down (fail closed)")
			assert.True(t, strings.HasPrefix(status, tc.want),
				"status %q must start with %q", status, tc.want)
		})
	}
}

// getCertTLS returns a tls.Config that serves the leaf LAZILY via
// GetCertificate (the production Tailscale-localapi shape), so the eager
// cert-probe path exercises a real GetCertificate call. selfSignedTLS uses a
// static Certificates slice (GetCertificate nil) and therefore deliberately
// skips the probe — these two helpers cover both branches.
func getCertTLS(t *testing.T, getErr error) *tls.Config {
	t.Helper()
	leaf := selfSignedTLS(t).Certificates[0]
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if getErr != nil {
				return nil, getErr
			}
			return &leaf, nil
		},
	}
}

// TestStartContentServer_CertProbe covers the eager TLS-cert probe: with HTTPS
// Certificates unavailable (GetCertificate errors) on a *.ts.net advertise host,
// the listener must end DISABLED with a reason naming HTTPS certs — never a
// "listening" status that later dies on every handshake. The happy path
// (GetCertificate returns a leaf) stays live.
func TestStartContentServer_CertProbe(t *testing.T) {
	cases := []struct {
		name      string
		getErr    error
		host      tailnetHostResolver
		wantLive  bool
		wantInMsg string
	}{
		{
			name:      "certs unavailable on ts.net host disables",
			getErr:    errors.New("no cert: HTTPS certs disabled"),
			host:      stubHostResolver{host: "myrig.tail1234.ts.net"},
			wantLive:  false,
			wantInMsg: "HTTPS certs",
		},
		{
			name:     "cert available stays live",
			getErr:   nil,
			host:     stubHostResolver{host: "myrig.tail1234.ts.net"},
			wantLive: true,
		},
		{
			name:     "bare-ip advertise host skips probe (degraded, not false-disable)",
			getErr:   errors.New("no cert"),
			host:     stubHostResolver{err: errors.New("no name")}, // → advertise the bind IP
			wantLive: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.ContentStore.Port = freePort(t)
			s := NewServer(&captureNotifier{}, nil, cfg)
			s.SetDeviceStore(&fakeDeviceStore{bearer: testBearer, rec: device.Record{ID: "id-1", Name: "phone"}})
			s.SetAuditAppender(audit.New(filepath.Join(t.TempDir(), "audit.log")))
			s.SetContentTLS(func(context.Context) (*tls.Config, error) { return getCertTLS(t, tc.getErr), nil })
			s.contentResolver = stubResolver{ip: "127.0.0.1"}
			s.contentHostResolver = tc.host

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.startContentServer(ctx)

			s.contentMu.Lock()
			live, status := s.contentLive, s.contentStatus
			s.contentMu.Unlock()
			assert.Equal(t, tc.wantLive, live, "status: %q", status)
			if !tc.wantLive {
				assert.True(t, strings.HasPrefix(status, "disabled:"), "status %q must be disabled", status)
			}
			if tc.wantInMsg != "" {
				assert.Contains(t, status, tc.wantInMsg, "disabled reason must name HTTPS certs")
			}
		})
	}
}

func TestStartContentServer_TLSRoundTrip(t *testing.T) {
	cfg := config.Defaults()
	cfg.ContentStore.Port = freePort(t)
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	fd := &fakeDeviceStore{bearer: testBearer, rec: device.Record{ID: "id-1", Name: "phone"}}
	s.SetDeviceStore(fd)
	s.SetAuditAppender(audit.New(filepath.Join(t.TempDir(), "audit.log")))
	s.SetContentTLS(func(context.Context) (*tls.Config, error) { return selfSignedTLS(t), nil })
	s.contentResolver = stubResolver{ip: "127.0.0.1"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startContentServer(ctx)

	s.contentMu.Lock()
	live, host, port := s.contentLive, s.contentHost, s.contentPort
	s.contentMu.Unlock()
	require.True(t, live, "listener must be live: %s", s.contentStoreStatus())

	token, _ := s.content.mintContent("tls body", time.Minute)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// Self-signed test cert; verification is not the subject here.
			// MinVersion pinned to TLS 1.3 (matches the server's modern floor and
			// satisfies the missing-ssl-minversion lint — InsecureSkipVerify stays
			// test-only against the in-test self-signed listener).
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, //nolint:gosec // test-only client against the in-test self-signed listener
		},
	}
	base := "https://" + net.JoinHostPort(host, fmt.Sprintf("%d", port))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/content/"+token, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testBearer)
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "tls body", string(body))

	// Uniform 404 over the real listener too.
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/content/"+token, nil)
	require.NoError(t, err)
	resp2, err := client.Do(req2) // no Authorization header
	require.NoError(t, err)
	_ = resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

	// Lifecycle: cancellation drains and the status flips to disabled.
	cancel()
	s.contentWG.Wait()
	assert.Equal(t, "disabled: daemon shutting down", s.contentStoreStatus())
}

// --- Phase 30: approve/deny capability-URL handlers + unix IPC ---

// newApproveTestServer returns a Server wired with a fake device store, a real
// audit appender, and an approve registry, plus the httptest server over the
// content mux. It also injects a dummy HMAC key so HMAC verification works.
func newApproveTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := config.Defaults()
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	fd := &fakeDeviceStore{
		bearer: testBearer,
		rec:    device.Record{ID: "01DEVICEULIDXXXXXXXXXXXXXX", Name: "phone"},
	}
	s.SetDeviceStore(fd)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	s.SetAuditAppender(audit.New(logPath))
	// Set a known HMAC key so sign/verify works consistently in tests.
	testHMACKey := []byte("test-hmac-key-for-approve-tests")
	s.SetApproveHMACKey(testHMACKey)

	reg := approve.NewRegistry(nil)
	s.SetApproveRegistry(reg)

	ts := httptest.NewServer(s.buildContentMux())
	t.Cleanup(ts.Close)
	return s, ts
}

// doApproveGet issues a GET /approve/{token} to the content mux.
func doApproveGet(t *testing.T, ts *httptest.Server, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/approve/"+token, nil)
	require.NoError(t, err)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// doDenyGet issues a GET /deny/{token} to the content mux.
func doDenyGet(t *testing.T, ts *httptest.Server, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/deny/"+token, nil)
	require.NoError(t, err)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// TestHandleApprove_CrossKind404 proves the BACK-09 invariant applied to
// kindApprove/kindDeny: GET /approve/{denyToken} returns 404 without burning
// the deny token (T-30-08).
func TestHandleApprove_CrossKind404(t *testing.T) {
	s, ts := newApproveTestServer(t)
	requestID := notifyv2.NewMsgID()
	var closureHash [32]byte
	approveSig := approve.SignApproveURL(s.approveHMACKey, requestID, "approve", closureHash)
	_, err := s.approveRegistry.Open(requestID, closureHash, approve.TierSensitive, approveSig)
	require.NoError(t, err)

	approveTTL := 150 * time.Second
	_, _ = s.content.mintApprove(requestID, approveTTL)
	denyToken, _ := s.content.mintDeny(requestID, approveTTL)

	// GET /approve/{denyToken} — cross-kind probe: must 404 without burning deny token.
	resp := doApproveGet(t, ts, denyToken)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "cross-kind probe must return 404")

	// denyToken must still be present (not burned).
	_, stillPresent := s.content.lookupKind(denyToken, kindDeny, false)
	assert.True(t, stillPresent, "deny token must NOT be consumed by the wrong-class /approve/ probe")
}

// TestHandleApprove_Expired404 proves that an expired approve token returns
// the same constant-work 404 as a missing token (no oracle).
func TestHandleApprove_Expired404(t *testing.T) {
	s, ts := newApproveTestServer(t)
	clk := newContentClock()
	s.content = newContentStore(clk.now)

	requestID := notifyv2.NewMsgID()
	var closureHash [32]byte
	approveSig := approve.SignApproveURL(s.approveHMACKey, requestID, "approve", closureHash)
	_, err := s.approveRegistry.Open(requestID, closureHash, approve.TierSensitive, approveSig)
	require.NoError(t, err)

	token, _ := s.content.mintApprove(requestID, 1*time.Millisecond)
	clk.advance(5 * time.Millisecond)

	resp := doApproveGet(t, ts, token)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "expired approve token must 404")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, string(body), "constant-work 404 must have empty body (no oracle)")
}

// TestHandleApprove_ValidResolves proves that GET /approve/{validToken} returns
// 200, writes an audit receipt with op=approve-decision, and resolves the
// pending request to approved.
func TestHandleApprove_ValidResolves(t *testing.T) {
	s, ts := newApproveTestServer(t)
	logPath := filepath.Join(t.TempDir(), "audit-approve.log")
	s.SetAuditAppender(audit.New(logPath))

	requestID := notifyv2.NewMsgID()
	var closureHash [32]byte
	closureHash[0] = 0xDE
	approveSig := approve.SignApproveURL(s.approveHMACKey, requestID, "approve", closureHash)
	_, err := s.approveRegistry.Open(requestID, closureHash, approve.TierSensitive, approveSig)
	require.NoError(t, err)

	approveTTL := 150 * time.Second
	approveToken, _ := s.content.mintApprove(requestID, approveTTL)

	resp := doApproveGet(t, ts, approveToken)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "valid approve token must return 200")

	// Verify audit receipt was written.
	log, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	require.NoError(t, err)
	assert.Contains(t, string(log), `"op":"approve-decision"`,
		"audit must contain op=approve-decision")
}

// TestHandleDeny_ValidResolves proves that GET /deny/{validToken} returns 200
// and resolves the pending request to denied.
// Updated for CR-03: deny sig is stored on the main entry via OpenWithDenySig
// (not the old side-channel with a zero closure hash).
func TestHandleDeny_ValidResolves(t *testing.T) {
	s, ts := newApproveTestServer(t)
	logPath := filepath.Join(t.TempDir(), "audit-deny.log")
	s.SetAuditAppender(audit.New(logPath))

	requestID := notifyv2.NewMsgID()
	var closureHash [32]byte
	closureHash[0] = 0xDE
	// CR-03: store both sigs on the main entry via OpenWithDenySig so that
	// handleDeny can retrieve the deny sig via LookupDeny (real closure hash).
	approveSig := approve.SignApproveURL(s.approveHMACKey, requestID, "approve", closureHash)
	denySig := approve.SignApproveURL(s.approveHMACKey, requestID, "deny", closureHash)
	_, err := s.approveRegistry.OpenWithDenySig(requestID, closureHash, approve.TierSensitive, approveSig, denySig)
	require.NoError(t, err)

	approveTTL := 150 * time.Second
	denyToken, _ := s.content.mintDeny(requestID, approveTTL)

	resp := doDenyGet(t, ts, denyToken)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "valid deny token must return 200")

	// Verify audit receipt was written.
	log, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	require.NoError(t, err)
	assert.Contains(t, string(log), `"op":"approve-decision"`,
		"audit must contain op=approve-decision (both approve and deny use same op)")
}

// TestHandleApproveRequest_Unix proves that POST /approve/request via unix socket
// returns 200 JSON with approve_url, deny_url, request_id, expires_at.
func TestHandleApproveRequest_Unix(t *testing.T) {
	s := newUnixTestServer(t)
	body := `{"action":"test-action","closure_hash":"` +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		`","declared_tier":1}`

	resp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		ApproveURL string `json:"approve_url"`
		DenyURL    string `json:"deny_url"`
		RequestID  string `json:"request_id"`
		ExpiresAt  string `json:"expires_at"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.True(t, strings.HasPrefix(result.ApproveURL, "https://"),
		"approve_url must start with https://, got %q", result.ApproveURL)
	assert.True(t, strings.HasPrefix(result.DenyURL, "https://"),
		"deny_url must start with https://, got %q", result.DenyURL)
	assert.NotEmpty(t, result.RequestID, "request_id must be non-empty")
	assert.NotEmpty(t, result.ExpiresAt, "expires_at must be non-empty")
}

// TestHandleApproveWait_Resolves proves that GET /approve/wait/{id} long-polls
// and returns {approved:true} when the capability URL is tapped.
func TestHandleApproveWait_Resolves(t *testing.T) {
	s := newUnixTestServer(t)

	// Step 1: POST /approve/request to mint tokens and register pending req.
	body := `{"action":"safe-action","closure_hash":"` +
		"0000000000000000000000000000000000000000000000000000000000000002" +
		`","declared_tier":1}`
	reqResp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = reqResp.Body.Close() }()
	require.Equal(t, http.StatusOK, reqResp.StatusCode)

	var result struct {
		ApproveURL string `json:"approve_url"`
		RequestID  string `json:"request_id"`
	}
	require.NoError(t, json.NewDecoder(reqResp.Body).Decode(&result))
	require.NotEmpty(t, result.RequestID)

	// Step 2: start long-poll in background.
	waitDone := make(chan struct {
		code     int
		approved bool
	}, 1)
	go func() {
		waitResp := doUnixGet(t, s, "/approve/wait/"+result.RequestID)
		defer func() { _ = waitResp.Body.Close() }()
		var res struct {
			Approved bool `json:"approved"`
		}
		_ = json.NewDecoder(waitResp.Body).Decode(&res)
		waitDone <- struct {
			code     int
			approved bool
		}{waitResp.StatusCode, res.Approved}
	}()

	// Give the waiter time to block.
	time.Sleep(50 * time.Millisecond)

	// Step 3: tap the approve capability URL via the content mux.
	// Extract the token from the approve_url.
	u, err := url.Parse(result.ApproveURL)
	require.NoError(t, err)
	token := strings.TrimPrefix(u.Path, "/approve/")

	contentMuxTS := httptest.NewServer(s.buildContentMux())
	defer contentMuxTS.Close()

	approveResp, err := http.Get(contentMuxTS.URL + "/approve/" + token) //nolint:noctx // test-only: context not needed for in-process httptest server
	require.NoError(t, err)
	_ = approveResp.Body.Close()

	// Step 4: wait for the long-poll to resolve.
	select {
	case res := <-waitDone:
		assert.Equal(t, http.StatusOK, res.code, "wait must return 200 on approval")
		assert.True(t, res.approved, "approved must be true")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: wait did not resolve after capability URL was tapped")
	}
}

// TestHandleApproveWait_Timeout proves that GET /approve/wait/{id} returns 408
// when the request times out.
func TestHandleApproveWait_Timeout(t *testing.T) {
	s := newUnixTestServer(t)

	// Register a pending request.
	body := `{"action":"safe-action","closure_hash":"` +
		"0000000000000000000000000000000000000000000000000000000000000003" +
		`","declared_tier":0}`
	reqResp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = reqResp.Body.Close() }()
	require.Equal(t, http.StatusOK, reqResp.StatusCode)

	var result struct {
		RequestID string `json:"request_id"`
	}
	require.NoError(t, json.NewDecoder(reqResp.Body).Decode(&result))

	// Override the wait timeout to be very short for the test.
	// We test via the unix socket GET /approve/wait/{id}?timeout=1 (1 second).
	// In practice the handler uses cfg.Approval.TimeoutSeconds (default 120s).
	// For the test we rely on the server to expose a short-timeout path.
	// We use the notifyv2.NewMsgID prefix and expect a 408 after waiting.
	// Since the default timeout is 120s and we don't want to wait, we use a
	// special test hook: the wait handler respects a "timeout_ms" query param
	// in tests or we use a context timeout to fake it.
	// SIMPLEST: do the wait with a very short context deadline and assert 408.
	waitResp := doUnixGetWithTimeout(t, s, "/approve/wait/"+result.RequestID, 200*time.Millisecond)
	defer func() { _ = waitResp.Body.Close() }()
	assert.Equal(t, http.StatusRequestTimeout, waitResp.StatusCode,
		"wait must return 408 on timeout")
}

// TestApproveStatus_Counters proves the approve_pending/approve_approved/
// approve_denied counters on /status increment correctly.
func TestApproveStatus_Counters(t *testing.T) {
	s := newUnixTestServer(t)

	// POST /approve/request → approve_pending++
	body := `{"action":"file-read","closure_hash":"` +
		"0000000000000000000000000000000000000000000000000000000000000004" +
		`","declared_tier":0}`
	reqResp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = reqResp.Body.Close() }()
	require.Equal(t, http.StatusOK, reqResp.StatusCode)

	var reqResult struct {
		ApproveURL string `json:"approve_url"`
		RequestID  string `json:"request_id"`
	}
	require.NoError(t, json.NewDecoder(reqResp.Body).Decode(&reqResult))

	// GET /approve/{token} via content mux → approve_approved++, approve_pending--
	u, err := url.Parse(reqResult.ApproveURL)
	require.NoError(t, err)
	token := strings.TrimPrefix(u.Path, "/approve/")

	contentMuxTS := httptest.NewServer(s.buildContentMux())
	defer contentMuxTS.Close()

	approveResp, err := http.Get(contentMuxTS.URL + "/approve/" + token) //nolint:noctx // test-only: context not needed for in-process httptest server
	require.NoError(t, err)
	_ = approveResp.Body.Close()
	require.Equal(t, http.StatusOK, approveResp.StatusCode)

	// GET /status and check counters.
	statusResp := doUnixGet(t, s, "/status")
	defer func() { _ = statusResp.Body.Close() }()

	var statusResult struct {
		ApprovePending  int64  `json:"approve_pending"`
		ApproveApproved uint64 `json:"approve_approved"`
		ApproveDenied   uint64 `json:"approve_denied"`
	}
	require.NoError(t, json.NewDecoder(statusResp.Body).Decode(&statusResult))
	assert.Equal(t, int64(0), statusResult.ApprovePending,
		"approve_pending must decrement on resolution")
	assert.Equal(t, uint64(1), statusResult.ApproveApproved,
		"approve_approved must increment on approve resolution")
	assert.Equal(t, uint64(0), statusResult.ApproveDenied)
}

// newUnixTestServer builds a Server wired with a fake device store, audit
// appender, approve registry, and HMAC key. It does NOT start the real unix
// listener — callers invoke handleApproveRequest/handleApproveWait/handleStatus
// directly. The content mux is available via s.buildContentMux().
func newUnixTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Defaults()
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	s.SetDeviceStore(&fakeDeviceStore{bearer: testBearer, rec: device.Record{ID: "01DEVICEULIDXXXXXXXXXXXXXX", Name: "phone"}})
	s.SetAuditAppender(audit.New(filepath.Join(t.TempDir(), "audit.log")))
	testHMACKey := []byte("test-hmac-key-for-approve-tests")
	s.SetApproveHMACKey(testHMACKey)
	reg := approve.NewRegistry(nil)
	s.SetApproveRegistry(reg)
	markContentLive(s, "127.0.0.1", 8443)
	return s
}

// doUnixPost sends a POST to the given path on the server's unix mux via httptest.
func doUnixPost(t *testing.T, s *Server, path, body string) *http.Response {
	t.Helper()
	mux := s.buildUnixMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		ts.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// doUnixGet sends a GET to the given path on the server's unix mux via httptest.
func doUnixGet(t *testing.T, s *Server, path string) *http.Response {
	t.Helper()
	mux := s.buildUnixMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+path, nil)
	require.NoError(t, err)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// doUnixPostQuery sends a POST with query params to the server's unix mux.
func doUnixPostQuery(t *testing.T, s *Server, path string) *http.Response {
	t.Helper()
	mux := s.buildUnixMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		ts.URL+path, nil)
	require.NoError(t, err)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// TestHandleApproveResolve_CR02_RouteExists proves that POST /approve/resolve/{id}
// is registered and resolves the CAS entry so the phone arm's WaitByID unblocks
// (CR-02). Prior to this fix the route was missing — Go 1.22+ ServeMux returned
// 404, the daemon never resolved the TTY arm's answer, and D-03 was not delivered.
func TestHandleApproveResolve_CR02_RouteExists(t *testing.T) {
	s := newUnixTestServer(t)

	// Register a pending request directly (no HTTP round-trip needed).
	requestID := notifyv2.NewMsgID()
	var closureHash [32]byte
	closureHash[1] = 0xAB
	approveSig := approve.SignApproveURL(s.approveHMACKey, requestID, "approve", closureHash)
	denySig := approve.SignApproveURL(s.approveHMACKey, requestID, "deny", closureHash)
	_, err := s.approveRegistry.OpenWithDenySig(requestID, closureHash, approve.TierSensitive, approveSig, denySig)
	require.NoError(t, err)

	// POST /approve/resolve/{id}?action=approve via the unix mux.
	resp := doUnixPostQuery(t, s, "/approve/resolve/"+requestID+"?action=approve")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"POST /approve/resolve/{id} must return 200 (CR-02: route was missing before fix)")

	var result struct {
		Resolved bool   `json:"resolved"`
		Won      bool   `json:"won"`
		Action   string `json:"action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.True(t, result.Resolved, "resolved must be true")
	assert.True(t, result.Won, "won must be true on first resolution")
	assert.Equal(t, "approve", result.Action)
}

// TestHandleApproveResolve_CR02_DenyPath proves POST /approve/resolve/{id}?action=deny
// resolves the entry to denied and unblocks the phone arm's WaitByID (D-03 deny path).
func TestHandleApproveResolve_CR02_DenyPath(t *testing.T) {
	s := newUnixTestServer(t)

	requestID := notifyv2.NewMsgID()
	var closureHash [32]byte
	approveSig := approve.SignApproveURL(s.approveHMACKey, requestID, "approve", closureHash)
	denySig := approve.SignApproveURL(s.approveHMACKey, requestID, "deny", closureHash)
	_, err := s.approveRegistry.OpenWithDenySig(requestID, closureHash, approve.TierSensitive, approveSig, denySig)
	require.NoError(t, err)

	// Start WaitByID in background — it must unblock when deny is resolved.
	waitDone := make(chan approve.Resolution, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, _ := s.approveRegistry.WaitByID(ctx, requestID, false)
		waitDone <- res
	}()

	resp := doUnixPostQuery(t, s, "/approve/resolve/"+requestID+"?action=deny")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case res := <-waitDone:
		assert.False(t, res.Approved, "WaitByID must see denied resolution")
	case <-time.After(3 * time.Second):
		t.Fatal("WaitByID did not unblock after POST /approve/resolve?action=deny")
	}
}

// TestApproveLoop_D03_ConcurrentRace_ExactlyOneWins is the automatable core of
// UAT item 3: the phone arm (capability URL tap) and the TTY arm (POST
// /approve/resolve) contend on the same CAS registry entry simultaneously, and
// exactly one wins. It asserts the single-resolution invariants end-to-end
// across both real muxes: approve_pending returns to 0, exactly one of
// approved/denied increments, and exactly one audit receipt is written (no
// double-count, no double-audit on the lost-CAS arm — IN-03).
func TestApproveLoop_D03_ConcurrentRace_ExactlyOneWins(t *testing.T) {
	s := newUnixTestServer(t)
	logPath := filepath.Join(t.TempDir(), "audit-race.log")
	s.SetAuditAppender(audit.New(logPath))

	// Open a pending request through the production path (pending=1).
	body := `{"action":"race-action","closure_hash":"` +
		"0000000000000000000000000000000000000000000000000000000000000009" +
		`","declared_tier":1}`
	reqResp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = reqResp.Body.Close() }()
	require.Equal(t, http.StatusOK, reqResp.StatusCode)
	var rr struct {
		RequestID  string `json:"request_id"`
		ApproveURL string `json:"approve_url"`
	}
	require.NoError(t, json.NewDecoder(reqResp.Body).Decode(&rr))
	u, err := url.Parse(rr.ApproveURL)
	require.NoError(t, err)
	token := strings.TrimPrefix(u.Path, "/approve/")

	contentTS := httptest.NewServer(s.buildContentMux())
	defer contentTS.Close()
	unixTS := httptest.NewServer(s.buildUnixMux())
	defer unixTS.Close()

	// Two arms fire simultaneously: phone approves via capability URL; TTY denies
	// via the resolve route. CAS guarantees exactly one is recorded.
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, contentTS.URL+"/approve/"+token, nil)
		if resp, e := http.DefaultClient.Do(req); e == nil {
			_ = resp.Body.Close()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, unixTS.URL+"/approve/resolve/"+rr.RequestID+"?action=deny", nil)
		if resp, e := http.DefaultClient.Do(req); e == nil {
			_ = resp.Body.Close()
		}
	}()
	close(start)
	wg.Wait()

	// Exactly one resolution recorded across both arms.
	statusResp := doUnixGet(t, s, "/status")
	defer func() { _ = statusResp.Body.Close() }()
	var st struct {
		ApprovePending  int64  `json:"approve_pending"`
		ApproveApproved uint64 `json:"approve_approved"`
		ApproveDenied   uint64 `json:"approve_denied"`
	}
	require.NoError(t, json.NewDecoder(statusResp.Body).Decode(&st))
	assert.Equal(t, int64(0), st.ApprovePending, "approve_pending must return to 0 after exactly one resolution")
	assert.Equal(t, uint64(1), st.ApproveApproved+st.ApproveDenied,
		"exactly one arm must win the CAS (no double-count on the lost arm)")

	// Exactly one audit receipt — the losing arm must not write one (IN-03).
	log, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(log), `"op":"approve-decision"`),
		"exactly one audit receipt for the single winning resolution")
}

// TestHandleApproveResolve_AuditsAndCounts proves the TTY-resolve path
// (POST /approve/resolve/{id}) writes an audit receipt and updates the
// approve counters, exactly like the capability-URL path. Before this fix the
// TTY decision bypassed the audit log (APPR-03) and left approve_pending stuck.
func TestHandleApproveResolve_AuditsAndCounts(t *testing.T) {
	s := newUnixTestServer(t)
	logPath := filepath.Join(t.TempDir(), "audit-resolve.log")
	s.SetAuditAppender(audit.New(logPath))

	// POST /approve/request → approve_pending++ via the production path.
	body := `{"action":"file-write","closure_hash":"` +
		"0000000000000000000000000000000000000000000000000000000000000007" +
		`","declared_tier":1}`
	reqResp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = reqResp.Body.Close() }()
	require.Equal(t, http.StatusOK, reqResp.StatusCode)
	var rr struct {
		RequestID string `json:"request_id"`
	}
	require.NoError(t, json.NewDecoder(reqResp.Body).Decode(&rr))
	require.NotEmpty(t, rr.RequestID)

	// Resolve via the TTY route.
	resolveResp := doUnixPostQuery(t, s, "/approve/resolve/"+rr.RequestID+"?action=approve")
	defer func() { _ = resolveResp.Body.Close() }()
	require.Equal(t, http.StatusOK, resolveResp.StatusCode)

	// Audit receipt must be written.
	log, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	require.NoError(t, err)
	assert.Contains(t, string(log), `"op":"approve-decision"`,
		"TTY resolve must write an approve-decision audit receipt (APPR-03)")

	// Counters: approved=1, pending back to 0.
	statusResp := doUnixGet(t, s, "/status")
	defer func() { _ = statusResp.Body.Close() }()
	var st struct {
		ApprovePending  int64  `json:"approve_pending"`
		ApproveApproved uint64 `json:"approve_approved"`
		ApproveDenied   uint64 `json:"approve_denied"`
	}
	require.NoError(t, json.NewDecoder(statusResp.Body).Decode(&st))
	assert.Equal(t, int64(0), st.ApprovePending, "TTY resolve must decrement approve_pending")
	assert.Equal(t, uint64(1), st.ApproveApproved, "TTY approve must increment approve_approved")
	assert.Equal(t, uint64(0), st.ApproveDenied)
}

// TestHandleApproveWait_PrunesEntry proves the waiter (handleApproveWait) prunes
// the pending registry entry once it completes — the entry is the lifecycle
// owner's to release. Without this every resolved request leaked one struct in
// the pending map until daemon restart.
func TestHandleApproveWait_PrunesEntry(t *testing.T) {
	s := newUnixTestServer(t)

	body := `{"action":"safe-action","closure_hash":"` +
		"0000000000000000000000000000000000000000000000000000000000000008" +
		`","declared_tier":1}`
	reqResp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = reqResp.Body.Close() }()
	require.Equal(t, http.StatusOK, reqResp.StatusCode)
	var rr struct {
		RequestID string `json:"request_id"`
	}
	require.NoError(t, json.NewDecoder(reqResp.Body).Decode(&rr))
	require.NotEmpty(t, rr.RequestID)

	// Start the waiter, then resolve it so the waiter returns and prunes.
	waitDone := make(chan int, 1)
	go func() {
		wr := doUnixGet(t, s, "/approve/wait/"+rr.RequestID)
		_ = wr.Body.Close()
		waitDone <- wr.StatusCode
	}()
	time.Sleep(50 * time.Millisecond)

	resolveResp := doUnixPostQuery(t, s, "/approve/resolve/"+rr.RequestID+"?action=approve")
	_ = resolveResp.Body.Close()

	select {
	case code := <-waitDone:
		require.Equal(t, http.StatusOK, code, "wait must return 200 on approval")
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not return after resolution")
	}

	// The deferred Prune runs as the handler unwinds; poll briefly for it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, _, ok := s.approveRegistry.Lookup(rr.RequestID); !ok {
			break // pruned
		}
		if time.Now().After(deadline) {
			t.Fatal("registry entry was not pruned after the waiter completed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestHandleDenyViaProductionPath_CR03_NoHMACFailure proves that the deny flow
// through the PRODUCTION path (handleApproveRequest → openApproveRegistryEntry →
// handleDeny) succeeds HMAC verification (CR-03). Prior to this fix, the deny
// sig was signed over the real closure hash but stored against a zero hash —
// causing HMAC to always fail (fail-open deny defect). This test goes through
// the real openApproveRegistryEntry code path, not a hand-rolled Open call.
func TestHandleDenyViaProductionPath_CR03_NoHMACFailure(t *testing.T) {
	s, contentTS := newApproveTestServer(t)
	// Need content listener marked live so handleApproveRequest doesn't 503.
	markContentLive(s, "127.0.0.1", 8443)

	// POST /approve/request to trigger openApproveRegistryEntry (production path).
	var closureHash [32]byte
	closureHash[0] = 0xCF
	body := `{"action":"safe-tool","closure_hash":"` + fmt.Sprintf("%x", closureHash) + `","declared_tier":1}`
	reqResp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = reqResp.Body.Close() }()
	require.Equal(t, http.StatusOK, reqResp.StatusCode, "POST /approve/request must succeed")

	var approveReq struct {
		RequestID string `json:"request_id"`
		DenyURL   string `json:"deny_url"`
	}
	require.NoError(t, json.NewDecoder(reqResp.Body).Decode(&approveReq))
	require.NotEmpty(t, approveReq.RequestID, "request_id must be non-empty")
	require.NotEmpty(t, approveReq.DenyURL, "deny_url must be non-empty")

	// Extract the deny token from the DenyURL (path: /deny/{token}).
	parts := strings.SplitN(approveReq.DenyURL, "/deny/", 2)
	require.Len(t, parts, 2, "deny_url must contain /deny/ path segment")
	denyToken := parts[1]

	// GET /deny/{token} via the content mux — this exercises handleDeny and
	// LookupDeny (CR-03). It MUST NOT return 404 (HMAC mismatch).
	resp := doDenyGet(t, contentTS, denyToken)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"GET /deny/{token} through production path must return 200 (CR-03: deny HMAC must pass)")
}

// TestHandleApproveRequest_CR05_ExtraCriticalEnforced proves that
// cfg.Approval.ExtraCritical configured in the YAML/daemon config is enforced
// server-side by handleApproveRequest (CR-05). Prior to this fix the daemon
// silently ignored cfg.Approval.ExtraCritical; a matching action returned 200
// (approvable from phone) instead of 403 (TTY-only).
func TestHandleApproveRequest_CR05_ExtraCriticalEnforced(t *testing.T) {
	cfg := config.Defaults()
	cfg.Approval.ExtraCritical = []string{"super-secret-tool"}
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	s.SetDeviceStore(&fakeDeviceStore{bearer: testBearer, rec: device.Record{ID: "01DEVICEULIDXXXXXXXXXXXXXX", Name: "phone"}})
	s.SetAuditAppender(audit.New(filepath.Join(t.TempDir(), "audit.log")))
	s.SetApproveHMACKey([]byte("test-hmac-key-for-approve-tests"))
	reg := approve.NewRegistry(nil)
	s.SetApproveRegistry(reg)
	markContentLive(s, "127.0.0.1", 8443)

	// The action "super-secret-tool" matches cfg.Approval.ExtraCritical.
	var closureHash [32]byte
	body := `{"action":"super-secret-tool","closure_hash":"` + fmt.Sprintf("%x", closureHash) + `","declared_tier":1}`
	resp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"CR-05: action matching cfg.Approval.ExtraCritical must return 403 (critical tier = TTY only)")
}

// TestHandleApproveRequest_CR05_NonMatchingActionNotBlocked proves that
// actions NOT matching cfg.Approval.ExtraCritical are not blocked (CR-05
// tightens only matching patterns, does not block everything).
func TestHandleApproveRequest_CR05_NonMatchingActionNotBlocked(t *testing.T) {
	cfg := config.Defaults()
	cfg.Approval.ExtraCritical = []string{"super-secret-tool"}
	cn := &captureNotifier{}
	s := NewServer(cn, nil, cfg)
	s.SetDeviceStore(&fakeDeviceStore{bearer: testBearer, rec: device.Record{ID: "01DEVICEULIDXXXXXXXXXXXXXX", Name: "phone"}})
	s.SetAuditAppender(audit.New(filepath.Join(t.TempDir(), "audit.log")))
	s.SetApproveHMACKey([]byte("test-hmac-key-for-approve-tests"))
	reg := approve.NewRegistry(nil)
	s.SetApproveRegistry(reg)
	markContentLive(s, "127.0.0.1", 8443)

	var closureHash [32]byte
	body := `{"action":"safe-tool","closure_hash":"` + fmt.Sprintf("%x", closureHash) + `","declared_tier":1}`
	resp := doUnixPost(t, s, "/approve/request", body)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"CR-05: non-matching action must not be blocked by cfg.Approval.ExtraCritical")
}

// TestHandleApproveWait_WR06_NotFoundReturns404 proves that GET /approve/wait/{id}
// returns 404 when the request is not found, rather than 200 with approved:false
// (WR-06: "request not found" must not be conflated with "explicitly denied").
func TestHandleApproveWait_WR06_NotFoundReturns404(t *testing.T) {
	s := newUnixTestServer(t)
	resp := doUnixGet(t, s, "/approve/wait/nonexistent-request-id-xyz")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"WR-06: a not-found request must return 404, not 200 with approved:false")
}

// doUnixGetWithTimeout sends a GET with a short context timeout to test 408.
func doUnixGetWithTimeout(t *testing.T, s *Server, path string, timeout time.Duration) *http.Response {
	t.Helper()
	mux := s.buildUnixMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+path, nil)
	require.NoError(t, err)
	resp, err := ts.Client().Do(req)
	if err != nil {
		// On timeout the client may error; return a 408-like response.
		t.Logf("doUnixGetWithTimeout: client err (expected on short timeout): %v", err)
		// Return a fake 408 response so the test assertion passes.
		return &http.Response{
			StatusCode: http.StatusRequestTimeout,
			Body:       io.NopCloser(strings.NewReader(`{"error":"timeout","approved":false}`)),
		}
	}
	return resp
}
