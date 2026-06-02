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

package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestNetBirdAdapter returns a netbirdAdapter pointed at the given test
// server base URL. The API key is read from the ABYSSLINK_NB_API_KEY env var
// via the lazy loader, so tests set it through t.Setenv where needed.
func newTestNetBirdAdapter(t *testing.T, baseURL string) *netbirdAdapter {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.NetBird.ServerURL = baseURL
	return newNetBirdAdapter(cfg, nil)
}

func TestListPostureChecks_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/posture-checks", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]nbPostureCheck{
			{ID: "pc1", Name: "os-version", Description: "minimum OS version"},
			{ID: "pc2", Name: "nb-version", Description: "minimum NetBird version"},
		})
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	checks, err := a.ListPostureChecks(context.Background())
	require.NoError(t, err)
	require.Len(t, checks, 2)
	assert.Equal(t, "pc1", checks[0].ID)
	assert.Equal(t, "os-version", checks[0].Name)
}

func TestListPostureChecks_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	_, err := a.ListPostureChecks(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}

func TestCreatePostureCheck_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/posture-checks", r.URL.Path)
		var req nbCreatePostureCheckRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "os-min", req.Name)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(nbPostureCheck{ID: "new1", Name: req.Name, Description: req.Description})
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	created, err := a.CreatePostureCheck(context.Background(), nbCreatePostureCheckRequest{
		Name:        "os-min",
		Description: "require minimum OS",
	})
	require.NoError(t, err)
	assert.Equal(t, "new1", created.ID)
	assert.Equal(t, "os-min", created.Name)
}

func TestDeletePostureCheck_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/posture-checks/pc1", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	err := a.DeletePostureCheck(context.Background(), "pc1")
	require.NoError(t, err)
}

func TestDeletePostureCheck_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	err := a.DeletePostureCheck(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
}

// TestDeletePostureCheck_RejectsPathTraversal verifies WR-01: an id containing a
// path separator or "../" segment is rejected outright (defence in depth) rather
// than redirecting the DELETE verb to a different resource.
func TestDeletePostureCheck_RejectsPathTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server must not be reached for an illegal id")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	for _, bad := range []string{"../groups/abc", "pc/../../x", "a/b", "", "  "} {
		err := a.DeletePostureCheck(context.Background(), bad)
		require.Error(t, err, "id %q must be rejected", bad)
	}
}

// TestDeletePostureCheck_EscapesSpecialChars verifies WR-01: an id with
// URL-significant characters (space, "?", "#") is percent-escaped into a single
// path segment rather than altering the request target.
func TestDeletePostureCheck_EscapesSpecialChars(t *testing.T) {
	const id = "pc one?x#y"
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path is the decoded path; it must contain the full id as a single
		// segment under /api/posture-checks/ with no extra path elements.
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	require.NoError(t, a.DeletePostureCheck(context.Background(), id))
	assert.Equal(t, "/api/posture-checks/"+id, gotPath)
}
