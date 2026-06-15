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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stageTestServer wires a Server over an httptest mux that registers ONLY the
// local /enroll/stage route (mirroring the unix mux, never buildContentMux) and
// sets the content listener fields directly under contentMu — the established
// field-set test seam.
func stageTestServer(t *testing.T, live bool) (*Server, *httptest.Server) {
	t.Helper()
	cfg := config.Defaults()
	s := NewServer(&captureNotifier{}, nil, cfg)
	s.contentMu.Lock()
	s.contentLive = live
	s.contentAdvertiseHost = "rig.example.ts.net"
	s.contentPort = 2587
	s.contentMu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll/stage", s.handleEnrollStage)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts
}

func doStage(t *testing.T, ts *httptest.Server, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/enroll/stage", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func TestHandleEnrollStage_RoundTrip(t *testing.T) {
	s, ts := stageTestServer(t, true)

	bundle := `{"device":"phone","bearer":"ablk_tok_xyz","ssh_private_key_pem":"PEM"}`
	resp := doStage(t, ts, `{"bundle":`+bundle+`,"ttl_seconds":0}`)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out enrollStageResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, 300, out.TTLSeconds, "ttl_seconds=0 resolves to the EffectiveEnrollTTL default")
	assert.True(t, strings.HasPrefix(out.URL, "https://rig.example.ts.net:2587/enroll/"), "url: %s", out.URL)

	// Extract the token and confirm the staged bundle resolves verbatim.
	token := strings.TrimPrefix(out.URL, "https://rig.example.ts.net:2587/enroll/")
	body, found := s.content.lookupKind(token, kindBootstrap, true)
	require.True(t, found, "staged bootstrap token must resolve")
	assert.JSONEq(t, bundle, body, "the staged body is the posted bundle verbatim")
}

// TestHandleEnrollStage_UsesConfiguredEnrollTTL proves the enroll_ttl_seconds
// knob is genuinely wired end-to-end: a ttl_seconds=0 request resolves to the
// daemon's CONFIGURED EffectiveEnrollTTL, not a hardcoded 300. The RoundTrip
// test uses config.Defaults() (0→300), which would still pass against a
// hardcoded constant; this one sets a NON-default value to catch that regression.
func TestHandleEnrollStage_UsesConfiguredEnrollTTL(t *testing.T) {
	cfg := config.Defaults()
	cfg.ContentStore.EnrollTTLSeconds = 600 // non-default, within [30,900]
	s := NewServer(&captureNotifier{}, nil, cfg)
	s.contentMu.Lock()
	s.contentLive = true
	s.contentAdvertiseHost = "rig.example.ts.net"
	s.contentPort = 2587
	s.contentMu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll/stage", s.handleEnrollStage)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	resp := doStage(t, ts, `{"bundle":{"device":"phone"},"ttl_seconds":0}`)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out enrollStageResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, 600, out.TTLSeconds,
		"ttl_seconds=0 must resolve to the CONFIGURED EffectiveEnrollTTL (600), proving the knob is wired")
}

func TestHandleEnrollStage_ListenerDisabled(t *testing.T) {
	s, ts := stageTestServer(t, false)

	resp := doStage(t, ts, `{"bundle":{"device":"phone"},"ttl_seconds":0}`)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "disabled listener → 503, never panic")
	assert.Equal(t, 0, s.content.len(), "store must be unchanged when the listener is disabled")
}

func TestHandleEnrollStage_TTLClamp(t *testing.T) {
	_, ts := stageTestServer(t, true)

	tests := []struct {
		name string
		ttl  int
		want int
	}{
		{name: "below floor clamps up", ttl: 5, want: 30},
		{name: "above ceiling clamps down", ttl: 5000, want: 900},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doStage(t, ts, `{"bundle":{"device":"phone"},"ttl_seconds":`+itoa(tc.ttl)+`}`)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var out enrollStageResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
			assert.Equal(t, tc.want, out.TTLSeconds)
		})
	}
}

func TestHandleEnrollStage_RejectsBadBody(t *testing.T) {
	_, ts := stageTestServer(t, true)

	t.Run("empty bundle", func(t *testing.T) {
		resp := doStage(t, ts, `{"bundle":null,"ttl_seconds":0}`)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("unknown field", func(t *testing.T) {
		resp := doStage(t, ts, `{"bundle":{"device":"phone"},"surprise":1}`)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("non-POST rejected", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/enroll/stage", nil)
		require.NoError(t, err)
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})

	t.Run("oversize body blocked", func(t *testing.T) {
		huge := strings.Repeat("a", maxStageBody+1024)
		resp := doStage(t, ts, `{"bundle":{"k":"`+huge+`"}}`)
		defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode, "MaxBytesReader must block an oversize body")
	})
}

// itoa avoids importing strconv solely for the table tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
