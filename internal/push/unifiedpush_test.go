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

package push_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/push"
	"github.com/abysslink/abysslink/internal/secrets"
)

// mockKeychain is a minimal secrets.KeychainStore for tests.
type mockKeychain struct {
	service  string
	account  string
	password string
	err      error
}

func (m *mockKeychain) Get(_ context.Context, service, account string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if service == m.service && account == m.account {
		return m.password, nil
	}
	return "", secrets.ErrNotFound
}

func (m *mockKeychain) Set(_ context.Context, _, _, _ string) error { return nil }
func (m *mockKeychain) Delete(_ context.Context, _, _ string) error { return nil }

// testMessage returns a minimal valid Wake for test use.
func testWake(endpointURL string) push.Wake {
	return push.Wake{
		DeviceID:      "device-001",
		Platform:      "unifiedpush",
		ProviderToken: endpointURL,
		Msg: notifyv2.Message{
			V:       2,
			MsgID:   "01JXMKQ0000TEST000000000001",
			Kind:    notifyv2.KindNeedsInput,
			Host:    "testhost",
			Title:   "needs input",
			Session: notifyv2.SessionRef{Session: "main", Pane: "%1"},
			Fetch: &notifyv2.FetchRef{
				URLTailnet: "https://100.100.0.1/content/01JXMKQ0000TEST000000000001",
				TTLSeconds: 300,
			},
		},
		CollapseID: "abc123",
	}
}

// TestUnifiedPushSend verifies a 200 response is treated as success and the
// correct headers and JSON keys are sent.
func TestUnifiedPushSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	push.SetUPHTTPClient(srv.Client())
	t.Cleanup(func() { push.SetUPHTTPClient(nil) })

	gw := push.NewUnifiedPushGateway(nil)
	w := testWake(srv.URL + "/notify")

	err := gw.Send(context.Background(), w)
	require.NoError(t, err, "Send must return nil for 200 response")
}

// TestUnifiedPushOpaque verifies the request body contains no body/content fields.
func TestUnifiedPushOpaque(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		captured, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	push.SetUPHTTPClient(srv.Client())
	t.Cleanup(func() { push.SetUPHTTPClient(nil) })

	gw := push.NewUnifiedPushGateway(nil)
	w := testWake(srv.URL + "/notify")

	err := gw.Send(context.Background(), w)
	require.NoError(t, err)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(captured, &payload))

	// Opaque-wake invariant: no body/content fields must appear.
	forbidden := []string{"body", "content", "text", "pane", "agent_output"}
	for _, key := range forbidden {
		assert.NotContains(t, payload, key, "payload must not contain field %q", key)
	}

	// Must contain msg_id.
	assert.Contains(t, payload, "msg_id", "payload must contain msg_id")
}

// TestUnifiedPushHeadersPresent verifies X-Title header is set.
func TestUnifiedPushHeadersPresent(t *testing.T) {
	var xTitle, xMsgID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xTitle = r.Header.Get("X-Title")
		xMsgID = r.Header.Get("X-Msg-Id")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	push.SetUPHTTPClient(srv.Client())
	t.Cleanup(func() { push.SetUPHTTPClient(nil) })

	gw := push.NewUnifiedPushGateway(nil)
	w := testWake(srv.URL + "/notify")

	err := gw.Send(context.Background(), w)
	require.NoError(t, err)

	assert.Equal(t, w.Msg.Title, xTitle, "X-Title must match message title")
	assert.Equal(t, w.Msg.MsgID, xMsgID, "X-Msg-Id must match msg_id")
}

// TestUnifiedPushAuthAttached verifies that when a keychain returns a password,
// Basic auth is attached to the request.
func TestUnifiedPushAuthAttached(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	push.SetUPHTTPClient(srv.Client())
	t.Cleanup(func() { push.SetUPHTTPClient(nil) })

	kc := &mockKeychain{service: "abysslink", account: "ntfy-password", password: "s3cr3t"}
	gw := push.NewUnifiedPushGateway(kc)
	w := testWake(srv.URL + "/notify")

	err := gw.Send(context.Background(), w)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(authHeader, "Basic "), "Authorization header must be Basic auth when keychain returns a password")
}

// TestUnifiedPushAuthMissing verifies that when no keychain is provided, no
// Authorization header is sent and Send succeeds.
func TestUnifiedPushAuthMissing(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	push.SetUPHTTPClient(srv.Client())
	t.Cleanup(func() { push.SetUPHTTPClient(nil) })

	gw := push.NewUnifiedPushGateway(nil) // nil keychain
	w := testWake(srv.URL + "/notify")

	err := gw.Send(context.Background(), w)
	require.NoError(t, err, "nil keychain must not cause an error")
	assert.Empty(t, authHeader, "no Authorization header must be sent when keychain is nil")
}

// TestUnifiedPushNon200 verifies that a non-2xx response returns an error
// containing the HTTP status code.
func TestUnifiedPushNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service down"))
	}))
	t.Cleanup(srv.Close)

	push.SetUPHTTPClient(srv.Client())
	t.Cleanup(func() { push.SetUPHTTPClient(nil) })

	gw := push.NewUnifiedPushGateway(nil)
	w := testWake(srv.URL + "/notify")

	err := gw.Send(context.Background(), w)
	require.Error(t, err, "non-2xx response must return an error")
	assert.Contains(t, err.Error(), "HTTP 503", "error must contain the HTTP status code")
}

// TestUnifiedPushDeadToken verifies that HTTP 404 and 410 (registration gone)
// map to push.ErrDeadToken so the retry goroutine prunes the device instead of
// retrying a decommissioned endpoint forever (finding [10]).
func TestUnifiedPushDeadToken(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusGone} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		t.Cleanup(srv.Close)

		push.SetUPHTTPClient(srv.Client())
		gw := push.NewUnifiedPushGateway(nil)
		err := gw.Send(context.Background(), testWake(srv.URL+"/notify"))
		assert.True(t, errors.Is(err, push.ErrDeadToken),
			"HTTP %d must return ErrDeadToken, got: %v", code, err)
	}
	push.SetUPHTTPClient(nil)
}
