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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func netbirdCfg(t *testing.T, serverURL string) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = serverURL
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test")
	return cfg
}

func TestNetBirdPostureListCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"id": "pc1", "name": "os-version", "description": "min OS"},
		})
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner()}
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	err := netbirdPostureListRunE(context.Background(), cc, p)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "pc1")
	assert.Contains(t, out.String(), "os-version")
}

func TestNetBirdPostureListCmd_JSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"id": "pc1", "name": "os-version", "description": "min OS"},
		})
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner(), jsonOut: true}
	out := &bytes.Buffer{}
	p := NewJSONPrinterTo(out, &bytes.Buffer{})

	err := netbirdPostureListRunE(context.Background(), cc, p)
	require.NoError(t, err)
	assert.Contains(t, out.String(), `"id":"pc1"`)
}

func TestNetBirdPostureCreateCmd(t *testing.T) {
	var gotName, gotDesc string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		_ = json.Unmarshal(body["name"], &gotName)
		_ = json.Unmarshal(body["description"], &gotDesc)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "new1", "name": gotName, "description": gotDesc})
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner(), apply: true}
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	err := netbirdPostureCreateRunE(context.Background(), cc, p, "my-check", "a description", "")
	require.NoError(t, err)
	assert.Equal(t, "my-check", gotName)
	assert.Equal(t, "a description", gotDesc)
	assert.Contains(t, out.String(), "new1")
}

// TestNetBirdPostureCreateCmd_DryRunDefault asserts the CLI-08 gate: without
// --apply, posture create sends NO request to the control plane and prints a
// [plan] preview instead.
func TestNetBirdPostureCreateCmd_DryRunDefault(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner(), dryRun: true}
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	err := netbirdPostureCreateRunE(context.Background(), cc, p, "my-check", "a description", "")
	require.NoError(t, err)
	assert.Equal(t, 0, hits, "dry-run must not hit the control plane")
	assert.Contains(t, out.String(), "[plan]", "dry-run must print a plan preview")
	assert.Contains(t, out.String(), "my-check")
}

// TestNetBirdPostureDeleteCmd_DryRunDefault asserts the CLI-08 gate: without
// --apply, posture delete sends NO request to the control plane.
func TestNetBirdPostureDeleteCmd_DryRunDefault(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner(), dryRun: true}
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	err := netbirdPostureDeleteRunE(context.Background(), cc, p, "pc1")
	require.NoError(t, err)
	assert.Equal(t, 0, hits, "dry-run must not hit the control plane")
	assert.Contains(t, out.String(), "[plan]", "dry-run must print a plan preview")
	assert.Contains(t, out.String(), "pc1")
}

func TestNetBirdPostureDeleteCmd(t *testing.T) {
	var deletedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner(), apply: true}
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	err := netbirdPostureDeleteRunE(context.Background(), cc, p, "pc1")
	require.NoError(t, err)
	assert.Equal(t, "/api/posture-checks/pc1", deletedPath)
	assert.Contains(t, out.String(), "pc1")
}
