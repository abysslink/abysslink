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
)

// newFCMTestClient wraps an httptest.Server into a plain *http.Client that
// adds a Bearer token so FCMGateway.Send doesn't need a real oauth2 flow in
// unit tests. The Authorization header is injected by headerTransport.
func newFCMTestClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &bearerTransport{
			inner:  srv.Client().Transport,
			bearer: "test-token",
		},
	}
}

// bearerTransport injects an Authorization: Bearer header onto every request.
type bearerTransport struct {
	inner  http.RoundTripper
	bearer string
}

func (bt *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+bt.bearer)
	return bt.inner.RoundTrip(clone)
}

// testFCMWake returns a Wake suitable for FCM send tests.
func testFCMWake() push.Wake {
	return push.Wake{
		DeviceID:      "device-fcm-001",
		Platform:      "fcm",
		ProviderToken: "fcm-device-registration-token-abc123",
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
		CollapseID: "deadbeef01234567",
	}
}

// TestFCMSend verifies the happy-path send: correct HTTP method, Content-Type,
// Authorization header presence, token in message body, and android.priority=high.
func TestFCMSend(t *testing.T) {
	var (
		capturedMethod      string
		capturedContentType string
		capturedAuthHeader  string
		capturedBody        []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedContentType = r.Header.Get("Content-Type")
		capturedAuthHeader = r.Header.Get("Authorization")
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"projects/test-project/messages/0:1"}`))
	}))
	defer srv.Close()

	client := newFCMTestClient(t, srv)
	push.SetFCMAPIURL(srv.URL)
	t.Cleanup(func() { push.SetFCMAPIURL("") })

	gw := push.NewFCMGatewayForTest("test-project", client)
	w := testFCMWake()
	err := gw.Send(context.Background(), w)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, capturedMethod, "must be POST")
	assert.Equal(t, "application/json", capturedContentType, "Content-Type must be application/json")
	assert.True(t, strings.HasPrefix(capturedAuthHeader, "Bearer "), "Authorization must be Bearer")

	// Parse body and verify structure.
	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(capturedBody, &envelope), "body must be valid JSON")

	msgRaw, ok := envelope["message"]
	require.True(t, ok, "body must have 'message' key")

	var msg map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msgRaw, &msg), "message must be valid JSON")

	// token matches ProviderToken.
	var token string
	require.NoError(t, json.Unmarshal(msg["token"], &token))
	assert.Equal(t, w.ProviderToken, token, "message.token must match w.ProviderToken")

	// android.priority must be "high".
	androidRaw, ok := msg["android"]
	require.True(t, ok, "message must have 'android' key")
	var android map[string]string
	require.NoError(t, json.Unmarshal(androidRaw, &android))
	assert.Equal(t, "high", android["priority"], "android.priority must be 'high'")
}

// TestFCMDataAllStrings asserts that all values in message.data are JSON strings.
func TestFCMDataAllStrings(t *testing.T) {
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"projects/test-project/messages/0:1"}`))
	}))
	defer srv.Close()

	push.SetFCMAPIURL(srv.URL)
	t.Cleanup(func() { push.SetFCMAPIURL("") })

	gw := push.NewFCMGatewayForTest("test-project", newFCMTestClient(t, srv))
	require.NoError(t, gw.Send(context.Background(), testFCMWake()))

	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(capturedBody, &envelope))
	var msg map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["message"], &msg))

	dataRaw, ok := msg["data"]
	require.True(t, ok, "message must have 'data' key")

	var data map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(dataRaw, &data), "data must be valid JSON object")

	// Every value must be a JSON string (starts with '"').
	for k, v := range data {
		assert.True(t, len(v) >= 2 && v[0] == '"', "data[%q] must be a JSON string, got: %s", k, v)
	}
}

// TestFCMOpaque asserts that the request body JSON contains no key "body",
// "content", "text", or "pane" at any nesting level.
func TestFCMOpaque(t *testing.T) {
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"projects/test-project/messages/0:1"}`))
	}))
	defer srv.Close()

	push.SetFCMAPIURL(srv.URL)
	t.Cleanup(func() { push.SetFCMAPIURL("") })

	gw := push.NewFCMGatewayForTest("test-project", newFCMTestClient(t, srv))
	require.NoError(t, gw.Send(context.Background(), testFCMWake()))

	bodyStr := string(capturedBody)
	forbidden := []string{`"body"`, `"content"`, `"text"`, `"pane"`}
	for _, key := range forbidden {
		assert.NotContains(t, bodyStr, key,
			"FCM payload must not contain %s at any depth (opaque-wake invariant)", key)
	}
}

// TestFCMDeadToken verifies that a 404 with UNREGISTERED status returns ErrDeadToken.
func TestFCMDeadToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"status":"UNREGISTERED","message":"Token not registered"}}`))
	}))
	defer srv.Close()

	push.SetFCMAPIURL(srv.URL)
	t.Cleanup(func() { push.SetFCMAPIURL("") })

	gw := push.NewFCMGatewayForTest("test-project", newFCMTestClient(t, srv))
	err := gw.Send(context.Background(), testFCMWake())

	require.Error(t, err, "404 UNREGISTERED must return an error")
	assert.True(t, errors.Is(err, push.ErrDeadToken),
		"404 UNREGISTERED must return ErrDeadToken, got: %v", err)
}

// TestFCMOther404NotDead verifies that a 404 with a non-UNREGISTERED status
// does NOT return ErrDeadToken.
func TestFCMOther404NotDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"status":"SENDER_ID_MISMATCH","message":"Mismatched sender"}}`))
	}))
	defer srv.Close()

	push.SetFCMAPIURL(srv.URL)
	t.Cleanup(func() { push.SetFCMAPIURL("") })

	gw := push.NewFCMGatewayForTest("test-project", newFCMTestClient(t, srv))
	err := gw.Send(context.Background(), testFCMWake())

	require.Error(t, err, "404 with non-UNREGISTERED must return an error")
	assert.False(t, errors.Is(err, push.ErrDeadToken),
		"404 SENDER_ID_MISMATCH must NOT return ErrDeadToken")
}

// TestFCMProjectIDFromJSON verifies that NewFCMGateway extracts project_id from
// the service-account JSON (not from a config field), isolating the extraction
// logic from the oauth2 parse via the minimal credJSON approach.
func TestFCMProjectIDFromJSON(t *testing.T) {
	// We test the project_id extraction separately from oauth2 token flow.
	// NewFCMGatewayForTest skips oauth2 entirely; this test uses a helper
	// that exercises only the project_id extraction code path.
	projectID, err := push.ExtractFCMProjectID([]byte(`{"project_id":"my-proj","type":"service_account"}`))
	require.NoError(t, err)
	assert.Equal(t, "my-proj", projectID)
}

// TestFCMProjectIDMissing verifies that ExtractFCMProjectID returns an error
// when the project_id field is absent from the credential JSON.
func TestFCMProjectIDMissing(t *testing.T) {
	_, err := push.ExtractFCMProjectID([]byte(`{"type":"service_account"}`))
	require.Error(t, err, "missing project_id must return error")
}
