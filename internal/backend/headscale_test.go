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

package backend_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// headscaleCfg returns a minimal *config.Config for Headscale adapter tests.
// Backend.Type is "headscale"; Server.Headscale.ServerURL is set to serverURL.
func headscaleCfg(serverURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "headscale"
	cfg.Server.Headscale.ServerURL = serverURL
	return cfg
}

// newHeadscaleMockServer creates an httptest.Server that serves Headscale REST
// endpoints needed by the contract tests. The capturedPreAuthKeyBody channel
// receives the raw request body of any POST /api/v1/preauthkey call so callers
// can assert on the Expiration field. Pass nil to skip capturing.
//
// POST /api/v1/policy: the policyPushed atomic is incremented on each call
// so callers can assert that SetACL was invoked (e.g., during Up()).
func newHeadscaleMockServer(t *testing.T, policyPushed *atomic.Int32, capturedPreAuthKeyBody chan []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/node":
			serveFixture(w, "testdata/headscale_nodes.json")
		case "/api/v1/preauthkey":
			servePreAuthKey(w, r, capturedPreAuthKeyBody)
		case "/api/v1/policy":
			servePolicy(w, r, policyPushed)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serveFixture writes the contents of fixturePath to w, or 500 on error.
func serveFixture(w http.ResponseWriter, fixturePath string) {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		http.Error(w, "fixture missing: "+fixturePath, http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

// servePreAuthKey handles GET (list) and POST (create) on /api/v1/preauthkey.
func servePreAuthKey(w http.ResponseWriter, r *http.Request, captured chan []byte) {
	switch r.Method {
	case http.MethodGet:
		serveFixture(w, "testdata/headscale_preauthkeys.json")
	case http.MethodPost:
		capturePreAuthKeyBody(r, captured)
		resp := map[string]any{
			"preAuthKey": map[string]any{
				"id":         "99",
				"key":        "test-key-abc",
				"reusable":   false,
				"ephemeral":  true,
				"used":       false,
				"expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"createdAt":  time.Now().UTC().Format(time.RFC3339),
				"aclTags":    []string{"tag:mobile"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	default:
		http.NotFound(w, r)
	}
}

// capturePreAuthKeyBody reads the POST body and sends it to captured (non-blocking).
func capturePreAuthKeyBody(r *http.Request, captured chan []byte) {
	if captured == nil || r.Body == nil {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return
	}
	select {
	case captured <- buf:
	default:
	}
}

// servePolicy handles GET and PUT on /api/v1/policy.
func servePolicy(w http.ResponseWriter, r *http.Request, policyPushed *atomic.Int32) {
	switch r.Method {
	case http.MethodGet:
		serveFixture(w, "testdata/headscale_policy.json")
	case http.MethodPut:
		if policyPushed != nil {
			policyPushed.Add(1)
		}
		_, _ = w.Write([]byte(`{}`))
	default:
		http.NotFound(w, r)
	}
}

// TestContract_HeadscaleAdapter asserts the 3 mandated contract invariants
// against the headscale adapter driven by a mock httptest server and MockRunner.
func TestContract_HeadscaleAdapter(t *testing.T) {
	srv := newHeadscaleMockServer(t, nil, nil)

	b, err := backend.New(headscaleCfg(srv.URL), shell.NewMockRunner())
	require.NoError(t, err)

	ctx := context.Background()

	// Invariant #1: IP() returns a non-empty string.
	ip, err := b.IP(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, ip, "contract invariant #1: IP() must return a non-empty address")

	// Invariant #2: SSHConfig().CheckPeriod is non-zero.
	require.NotZero(t, b.SSHConfig().CheckPeriod,
		"contract invariant #2: SSHConfig().CheckPeriod must be non-zero")

	// Invariant #3: LockCapability() == LockNone (headscale-specific — no TKA).
	require.Equal(t, backend.LockNone, b.LockCapability(),
		"contract invariant #3: Headscale adapter must report LockNone")
}

// TestCapabilityInterfaceLockstep_Headscale asserts the lockstep invariant for
// the Headscale adapter: caps.Lock must be false AND the adapter must NOT satisfy
// the backend.Locker interface.
//
// This test is a permanent drift guard — if anyone accidentally adds LockStatus,
// LockInit, or LockSign methods to headscaleAdapter, this test will catch the
// violation before it reaches main (T-12-02-03).
func TestCapabilityInterfaceLockstep_Headscale(t *testing.T) {
	srv := newHeadscaleMockServer(t, nil, nil)

	b, err := backend.New(headscaleCfg(srv.URL), shell.NewMockRunner())
	require.NoError(t, err)

	caps := b.Capabilities()
	require.False(t, caps.Lock, "headscale: Capabilities().Lock must be false — TKA not available")

	_, isLocker := b.(backend.Locker)
	require.False(t, isLocker,
		"headscale: adapter must NOT implement backend.Locker — lockstep invariant violation")

	// AdminAPI and ACLManager must be present (consistent with caps).
	_, isAdmin := b.(backend.AdminAPI)
	require.Equal(t, caps.AdminAPI, isAdmin,
		"headscale: caps.AdminAPI must equal whether adapter implements backend.AdminAPI")

	_, isACL := b.(backend.ACLManager)
	require.Equal(t, caps.ACL, isACL,
		"headscale: caps.ACL must equal whether adapter implements backend.ACLManager")
}

// TestHeadscaleGetACL asserts that GetACL calls GET /api/v1/policy and returns
// non-empty bytes.
func TestHeadscaleGetACL(t *testing.T) {
	srv := newHeadscaleMockServer(t, nil, nil)

	b, err := backend.New(headscaleCfg(srv.URL), shell.NewMockRunner())
	require.NoError(t, err)

	aclMgr, ok := b.(backend.ACLManager)
	require.True(t, ok, "headscale adapter must implement backend.ACLManager")

	raw, _, err := aclMgr.GetACL(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, raw, "GetACL must return non-empty policy bytes")
}

// TestHeadscaleSetACL asserts that SetACL calls PUT /api/v1/policy without error.
func TestHeadscaleSetACL(t *testing.T) {
	srv := newHeadscaleMockServer(t, nil, nil)

	b, err := backend.New(headscaleCfg(srv.URL), shell.NewMockRunner())
	require.NoError(t, err)

	aclMgr, ok := b.(backend.ACLManager)
	require.True(t, ok, "headscale adapter must implement backend.ACLManager")

	// Push a minimal HuJSON deny-all policy.
	policy := []byte(`{"acls":[{"action":"deny","src":["*"],"dst":["*:*"]}]}`)
	require.NoError(t, aclMgr.SetACL(context.Background(), policy, ""))
}

// TestHeadscaleCreateAuthKey_HasExpiry captures the POST /api/v1/preauthkey
// request body and asserts that the Expiration field is non-zero and in the future.
// This is the issue #1579 prevention test (T-12-02-06).
func TestHeadscaleCreateAuthKey_HasExpiry(t *testing.T) {
	captured := make(chan []byte, 1)
	srv := newHeadscaleMockServer(t, nil, captured)

	b, err := backend.New(headscaleCfg(srv.URL), shell.NewMockRunner())
	require.NoError(t, err)

	adminAPI, ok := b.(backend.AdminAPI)
	require.True(t, ok, "headscale adapter must implement backend.AdminAPI")

	key, err := adminAPI.CreateAuthKey(context.Background(), []string{"tag:mobile"})
	require.NoError(t, err)
	require.NotEmpty(t, key, "CreateAuthKey must return a non-empty key string")

	// Inspect the captured request body.
	var body []byte
	select {
	case body = <-captured:
	default:
	}
	require.NotEmpty(t, body, "POST /api/v1/preauthkey body must be captured")

	var req map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &req), "POST body must be valid JSON")

	expiryRaw, ok := req["expiration"]
	require.True(t, ok, "POST body must include 'expiration' field (issue #1579 guard)")

	var expiry time.Time
	require.NoError(t, json.Unmarshal(expiryRaw, &expiry), "expiration must parse as time.Time")
	require.False(t, expiry.IsZero(), "expiration must not be zero (issue #1579 guard)")
	require.True(t, expiry.After(time.Now()), "expiration must be in the future")
}

// TestHeadscaleDenyAllOnUp asserts that Up() pushes the deny-all ACL baseline
// via PUT /api/v1/policy before returning (HS-01 SC-1).
//
// The mock runner seeds one call for "tailscale up" (the enrollment shell call);
// Up() must then hit PUT /api/v1/policy, incrementing policyPushed.
func TestHeadscaleDenyAllOnUp(t *testing.T) {
	var policyPushed atomic.Int32
	srv := newHeadscaleMockServer(t, &policyPushed, nil)

	// Up() fails fast when ABYSSLINK_HS_PREAUTHKEY is empty (WR-01), so seed a
	// non-empty pre-auth key for the enrollment shell call.
	t.Setenv("ABYSSLINK_HS_PREAUTHKEY", "tskey-auth-test-fixture")

	// Seed the MockRunner for "tailscale up --login-server ... --hostname ...".
	// MockRunner accepts any RunWithEnv call and returns success.
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 0},
	})

	b, err := backend.New(headscaleCfg(srv.URL), runner)
	require.NoError(t, err)

	err = b.Up(context.Background(), backend.UpOpts{Hostname: "test-laptop"})
	require.NoError(t, err)

	require.GreaterOrEqual(t, policyPushed.Load(), int32(1),
		"Up() must push deny-all ACL baseline via PUT /api/v1/policy before returning (HS-01 SC-1)")
}

// TestHeadscaleDevices asserts that Devices() calls GET /api/v1/node and returns
// the parsed device list.
func TestHeadscaleDevices(t *testing.T) {
	srv := newHeadscaleMockServer(t, nil, nil)

	b, err := backend.New(headscaleCfg(srv.URL), shell.NewMockRunner())
	require.NoError(t, err)

	adminAPI, ok := b.(backend.AdminAPI)
	require.True(t, ok, "headscale adapter must implement backend.AdminAPI")

	devices, err := adminAPI.Devices(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, devices, "Devices() must return at least one device from fixture")
	require.Equal(t, "my-laptop", devices[0].Name)
}
