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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/push"
)

// generateTestP8 generates a fresh EC P-256 private key encoded as PEM in
// PKCS#8 format, as expected by apns2/token.AuthKeyFromBytes (which calls
// x509.ParsePKCS8PrivateKey). Apple's real .p8 files are also PKCS#8-wrapped.
func generateTestP8(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate EC P-256 key")

	// MarshalPKCS8PrivateKey produces the PKCS#8 DER that AuthKeyFromBytes
	// expects. MarshalECPrivateKey produces SEC 1 format which x509.ParsePKCS8PrivateKey
	// rejects with "use ParseECPrivateKey instead for this key format".
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err, "marshal PKCS#8 private key")

	block := &pem.Block{
		Type:  "PRIVATE KEY", // PKCS#8 PEM type (not "EC PRIVATE KEY")
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block)
}

// newAPNsMockServer returns a TLS httptest server that handles APNs-shaped
// requests (POST /3/device/{token}). The handler calls responder for each
// request, allowing tests to vary the response.
//
// The apns2 Client.HTTPClient is replaced with srv.Client() so TLS works
// without a real cert.
func newAPNsMockServer(t *testing.T, responder func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(responder))
	cleanup := func() { srv.Close() }
	return srv, cleanup
}

// newTestAPNsGateway builds an APNsGateway pointed at srv with the supplied
// P8 bytes injected via a MockCredsSource. The apns2 client's HTTPClient is
// replaced with srv.Client() so it trusts the self-signed TLS cert.
func newTestAPNsGateway(t *testing.T, srv *httptest.Server, p8PEM []byte) *push.APNsGateway {
	t.Helper()

	creds := &push.MockCredsSource{}
	creds.SetAPNs(p8PEM, "TESTKEYID1", "TESTTEAMID1")

	push.SetAPNsBaseURL(srv.URL)
	t.Cleanup(func() { push.SetAPNsBaseURL("") })

	gw, err := push.NewAPNsGateway(context.Background(), creds, "com.example.test")
	require.NoError(t, err, "NewAPNsGateway must succeed with valid P8")

	// Override apns2 client HTTP transport so httptest TLS cert is trusted.
	push.SetAPNsHTTPClient(gw, srv.Client())
	return gw
}

// testAPNsWake returns a Wake suitable for APNs send tests.
func testAPNsWake() push.Wake {
	return push.Wake{
		DeviceID:      "device-apns-001",
		Platform:      "apns",
		ProviderToken: "abc123devicetoken", // the hex device token
		Msg: notifyv2.Message{
			V:       2,
			MsgID:   "01JXMKQ0000TEST000000000002",
			Kind:    notifyv2.KindNeedsInput,
			Host:    "testhost",
			Title:   "needs input",
			Session: notifyv2.SessionRef{Session: "main", Pane: "%1"},
			Fetch: &notifyv2.FetchRef{
				URLTailnet: "https://100.100.0.1/content/01JXMKQ0000TEST000000000002",
				TTLSeconds: 300,
			},
		},
		CollapseID: "deadbeef01234567",
	}
}

// TestAPNsPushTypeAlert asserts the apns-push-type header is "alert".
func TestAPNsPushTypeAlert(t *testing.T) {
	p8 := generateTestP8(t)
	var capturedPushType string

	srv, cleanup := newAPNsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPushType = r.Header.Get("apns-push-type")
		w.Header().Set("apns-id", "test-apns-id")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"apns-id":"test-apns-id"}`))
	})
	defer cleanup()

	gw := newTestAPNsGateway(t, srv, p8)
	err := gw.Send(context.Background(), testAPNsWake())
	require.NoError(t, err)

	assert.Equal(t, "alert", capturedPushType, "apns-push-type must be 'alert'")
}

// TestAPNsMutableContent verifies mutable-content=1 is set and
// content-available is absent (opaque wake — no background fetch type).
func TestAPNsMutableContent(t *testing.T) {
	p8 := generateTestP8(t)
	var capturedBody []byte

	srv, cleanup := newAPNsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	defer cleanup()

	gw := newTestAPNsGateway(t, srv, p8)
	err := gw.Send(context.Background(), testAPNsWake())
	require.NoError(t, err)

	// The apns2 library wraps payload inside {"aps":{...}, ...} at the top level.
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(capturedBody, &top))

	apsRaw, ok := top["aps"]
	require.True(t, ok, "payload must have 'aps' key")

	var aps map[string]interface{}
	require.NoError(t, json.Unmarshal(apsRaw, &aps))

	// mutable-content must be 1 (SPEC §5.2).
	mc, ok := aps["mutable-content"]
	assert.True(t, ok, "aps must contain mutable-content")
	assert.EqualValues(t, 1, mc, "mutable-content must be 1")

	// content-available must NOT be present (that's background push — D-14).
	_, hasCA := aps["content-available"]
	assert.False(t, hasCA, "aps must NOT contain content-available (background push type forbidden)")
}

// TestAPNsNoContent verifies no "body" or "body_content" field appears at any
// depth in the payload (opaque-wake invariant).
func TestAPNsNoContent(t *testing.T) {
	p8 := generateTestP8(t)
	var capturedBody []byte

	srv, cleanup := newAPNsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	defer cleanup()

	gw := newTestAPNsGateway(t, srv, p8)
	err := gw.Send(context.Background(), testAPNsWake())
	require.NoError(t, err)

	// Flatten the JSON to check for forbidden content-bearing keys at any depth.
	// Note: "pane" is a valid routing key (tmux pane ID); only body/content
	// text fields are forbidden per the opaque-wake invariant (T-29-02-1).
	bodyStr := string(capturedBody)
	forbidden := []string{`"body"`, `"body_content"`, `"agent_output"`}
	for _, key := range forbidden {
		assert.NotContains(t, bodyStr, key, "payload must not contain %s at any depth", key)
	}

	// AlertBody must not appear in aps (we only set AlertTitle).
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(capturedBody, &top))
	apsRaw, ok := top["aps"]
	require.True(t, ok)
	var aps map[string]interface{}
	require.NoError(t, json.Unmarshal(apsRaw, &aps))
	alert, hasAlert := aps["alert"]
	if hasAlert {
		alertMap, isMap := alert.(map[string]interface{})
		if isMap {
			_, hasBody := alertMap["body"]
			assert.False(t, hasBody, "aps.alert must not contain 'body' field")
		}
	}
}

// TestAPNs410DeadToken verifies that an HTTP 410 response returns ErrDeadToken.
func TestAPNs410DeadToken(t *testing.T) {
	p8 := generateTestP8(t)

	srv, cleanup := newAPNsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone) // 410
		_, _ = w.Write([]byte(`{"reason":"Unregistered"}`))
	})
	defer cleanup()

	gw := newTestAPNsGateway(t, srv, p8)
	err := gw.Send(context.Background(), testAPNsWake())

	require.Error(t, err, "410 must return an error")
	assert.True(t, errors.Is(err, push.ErrDeadToken), "410 must return ErrDeadToken, got: %v", err)
}

// TestAPNsCollapseID verifies the apns-collapse-id header matches the Wake's
// CollapseID field.
func TestAPNsCollapseID(t *testing.T) {
	p8 := generateTestP8(t)
	var capturedCollapseID string

	srv, cleanup := newAPNsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedCollapseID = r.Header.Get("apns-collapse-id")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	defer cleanup()

	gw := newTestAPNsGateway(t, srv, p8)
	w := testAPNsWake()
	w.CollapseID = "deadbeef01234567"

	err := gw.Send(context.Background(), w)
	require.NoError(t, err)

	assert.Equal(t, w.CollapseID, capturedCollapseID, "apns-collapse-id must match Wake.CollapseID")
}

// TestAPNs400NotPruned verifies that a 400 with reason "BadDeviceToken" does
// NOT return ErrDeadToken (only 410 triggers pruning — Pitfall 3).
func TestAPNs400NotPruned(t *testing.T) {
	p8 := generateTestP8(t)

	srv, cleanup := newAPNsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400
		_, _ = w.Write([]byte(`{"reason":"BadDeviceToken"}`))
	})
	defer cleanup()

	gw := newTestAPNsGateway(t, srv, p8)
	err := gw.Send(context.Background(), testAPNsWake())

	require.Error(t, err, "400 must return an error")
	assert.False(t, errors.Is(err, push.ErrDeadToken),
		"400 BadDeviceToken must NOT return ErrDeadToken (only 410 triggers pruning)")
}
