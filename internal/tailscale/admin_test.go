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

package tailscale_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/tailscale"
)

// newTestAdminClient creates an AdminClient pointed at the given test server.
func newTestAdminClient(t *testing.T, srv *httptest.Server) *tailscale.AdminClient {
	t.Helper()
	return tailscale.NewAdminClientWithBase("example.com", "client_PLACEHOLDER", "secret_PLACEHOLDER", srv.URL)
}

// tokenHandler responds to OAuth token requests.
func tokenHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "tok_PLACEHOLDER",
		"expires_in":   3600,
	})
}

func TestOAuthFlow(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			callCount++
			tokenHandler(w, r)
			return
		}
		// Any other endpoint — devices list.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"devices": []interface{}{},
		})
	}))
	defer srv.Close()

	client := newTestAdminClient(t, srv)

	// First call: should fetch token.
	_, err := client.Devices(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "token should be fetched once")

	// Second call: token is cached; no new token fetch.
	_, err = client.Devices(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "token should be reused")
}

func TestOAuthFlow_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "unauthorized"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestAdminClient(t, srv)
	_, err := client.Devices(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestGetACL(t *testing.T) {
	sampleACL := `{"tagOwners": {"tag:mobile": ["user@example.com"]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			tokenHandler(w, r)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/acl") {
			w.Header().Set("ETag", `"etag_PLACEHOLDER"`)
			w.Header().Set("Content-Type", "application/hujson")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sampleACL))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := newTestAdminClient(t, srv)
	acl, etag, err := client.GetACL(context.Background())
	require.NoError(t, err)
	assert.Equal(t, sampleACL, string(acl))
	assert.Equal(t, `"etag_PLACEHOLDER"`, etag)
}

func TestSetACL(t *testing.T) {
	var receivedETag string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			tokenHandler(w, r)
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/acl") {
			receivedETag = r.Header.Get("If-Match")
			var err error
			receivedBody, err = io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := newTestAdminClient(t, srv)
	aclBytes := []byte(`{"tagOwners": {}}`)
	err := client.SetACL(context.Background(), aclBytes, `"etag_PLACEHOLDER"`)
	require.NoError(t, err)
	assert.Equal(t, `"etag_PLACEHOLDER"`, receivedETag)
	assert.Equal(t, aclBytes, receivedBody)
}

func TestSetACL_ETagMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			tokenHandler(w, r)
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/acl") {
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"message": "precondition failed"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := newTestAdminClient(t, srv)
	err := client.SetACL(context.Background(), []byte(`{}`), `"stale_etag"`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "412")
}

func TestDevices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			tokenHandler(w, r)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/devices") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"devices": []map[string]interface{}{
					{"id": "device_1", "name": "laptop", "hostname": "my-laptop", "tags": []string{"tag:laptop"}},
					{"id": "device_2", "name": "phone", "hostname": "my-phone", "tags": []string{"tag:mobile"}},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := newTestAdminClient(t, srv)
	result, err := client.Devices(context.Background())
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "device_1", result[0].ID)
	assert.Equal(t, "my-laptop", result[0].Hostname)
	assert.Equal(t, "device_2", result[1].ID)
}

func TestCreateAuthKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			tokenHandler(w, r)
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/keys") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"key": "tskey-auth-PLACEHOLDER",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := newTestAdminClient(t, srv)
	key, err := client.CreateAuthKey(context.Background(), []string{"tag:laptop"})
	require.NoError(t, err)
	assert.Equal(t, "tskey-auth-PLACEHOLDER", key)
}

func TestManualMode_GetACL(t *testing.T) {
	// No credentials = manual mode.
	client := tailscale.NewAdminClient("example.com", "", "")
	_, _, err := client.GetACL(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manual mode")
}

func TestManualMode_SetACL(t *testing.T) {
	client := tailscale.NewAdminClient("example.com", "", "")
	err := client.SetACL(context.Background(), []byte(`{}`), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manual mode")
}
