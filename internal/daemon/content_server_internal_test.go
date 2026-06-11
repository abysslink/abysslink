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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/notifyv2"
)

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

// markContentLive simulates a live content listener at host:port.
func markContentLive(s *Server, host string, port int) {
	s.contentMu.Lock()
	s.contentLive = true
	s.contentHost = host
	s.contentPort = port
	s.contentStatus = "listening on " + net.JoinHostPort(host, fmt.Sprintf("%d", port))
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only client against the in-test self-signed listener
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
