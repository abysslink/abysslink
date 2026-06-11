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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// netbirdCfg returns a minimal *config.Config for NetBird adapter tests.
// Backend.Type is "netbird"; Server.NetBird.ServerURL is set to serverURL.
// AcceptNoSSHCheck is set to true to bypass the D-04 gate in tests.
// Tailnet.Hostname matches the mock peer name so the NET-07 local-peer
// identification resolves to the "test-laptop" entry served by the mock.
func netbirdCfg(serverURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = serverURL
	cfg.Server.NetBird.AcceptNoSSHCheck = true
	cfg.Tailnet.Hostname = "test-laptop"
	return cfg
}

// ── Mock NetBird REST API server ──────────────────────────────────────────

// nbTestState tracks calls made to the mock server so tests can assert
// that DELETE and POST were invoked in the expected order.
type nbTestState struct {
	deletedPolicyIDs []string
	createdPolicies  []map[string]any
	capturedAuthHdr  []string
}

// newNetBirdMockServer creates an httptest.Server that serves the NetBird
// REST endpoints needed by the netbird adapter and editor tests.
//
// The server state is captured in *nbTestState for post-call assertions.
// The mock serves:
//   - GET /api/peers — returns two test peers
//   - GET /api/groups — returns the "All" (system) group + "dev" group
//   - POST /api/groups — creates a group, returns it with a generated ID
//   - GET /api/policies — returns one allow-all policy on "All" group
//   - POST /api/policies — records the created policy, returns it with ID "created-policy-id"
//   - GET /api/policies/{id} — returns the policy by ID
//   - DELETE /api/policies/{id} — records the delete, returns 200
//   - GET /api/setup-keys — returns one active setup key
//   - POST /api/setup-keys — returns a new setup key
func newNetBirdMockServer(t *testing.T, state *nbTestState) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if hdr := r.Header.Get("Authorization"); hdr != "" {
			state.capturedAuthHdr = append(state.capturedAuthHdr, hdr)
		}
		serveNBRequest(w, r, state)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serveNBRequest dispatches an incoming request to the appropriate handler.
// Separated from newNetBirdMockServer to satisfy gocyclo complexity limit.
func serveNBRequest(w http.ResponseWriter, r *http.Request, state *nbTestState) { //nolint:gocyclo // test dispatch function: complexity is acceptable for a comprehensive mock server
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == "/api/peers":
		serveNBPeers(w)
	case r.Method == http.MethodGet && p == "/api/groups":
		serveNBGroups(w)
	case r.Method == http.MethodPost && p == "/api/groups":
		serveNBCreateGroup(w, r)
	case r.Method == http.MethodGet && p == "/api/policies":
		serveNBPolicies(w)
	case r.Method == http.MethodPost && p == "/api/policies":
		serveNBCreatePolicy(w, r, state)
	case r.Method == http.MethodDelete && isPoliciesPath(p):
		state.deletedPolicyIDs = append(state.deletedPolicyIDs, policyIDFrom(p))
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && isPoliciesPath(p):
		serveNBPolicyByID(w, policyIDFrom(p), state)
	case r.Method == http.MethodGet && p == "/api/setup-keys":
		serveNBSetupKeys(w)
	case r.Method == http.MethodPost && p == "/api/setup-keys":
		serveNBCreateSetupKey(w)
	default:
		http.NotFound(w, r)
	}
}

// isPoliciesPath returns true if the URL path has the form "/api/policies/{id}".
func isPoliciesPath(p string) bool {
	return len(p) > len("/api/policies/")
}

// policyIDFrom extracts the policy ID from a "/api/policies/{id}" URL path.
func policyIDFrom(p string) string {
	return p[len("/api/policies/"):]
}

// serveNBPeers serves two test peers.
func serveNBPeers(w http.ResponseWriter) {
	peers := []map[string]any{
		{
			"id":        "peer-1",
			"name":      "test-laptop",
			"hostname":  "test-laptop.local",
			"dns_label": "test-laptop.netbird.cloud",
			"ip":        "100.64.0.1",
			"connected": true,
			"groups":    []map[string]any{{"id": "group-all", "name": "All"}},
		},
		{
			"id":        "peer-2",
			"name":      "test-phone",
			"hostname":  "test-phone.local",
			"dns_label": "test-phone.netbird.cloud",
			"ip":        "100.64.0.2",
			"connected": false,
			"groups":    []map[string]any{{"id": "group-all", "name": "All"}},
		},
	}
	writeJSON(w, peers)
}

// serveNBGroups serves the "All" system group plus a "dev" group.
func serveNBGroups(w http.ResponseWriter) {
	groups := []map[string]any{
		{
			"id":     "group-all",
			"name":   "All",
			"issued": "system",
		},
		{
			"id":     "group-dev",
			"name":   "dev",
			"issued": "api",
		},
	}
	writeJSON(w, groups)
}

// serveNBCreateGroup creates a group and returns it with a generated ID.
func serveNBCreateGroup(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	name, _ := body["name"].(string)
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{
		"id":     "group-new-" + name,
		"name":   name,
		"issued": "api",
	})
}

// serveNBPolicies serves one allow-all policy on the "All" group.
func serveNBPolicies(w http.ResponseWriter) {
	policies := []map[string]any{
		{
			"id":      "policy-allow-all",
			"name":    "Default Policy",
			"enabled": true,
			"rules": []map[string]any{
				{
					"id":            "rule-allow-all",
					"name":          "allow-all-rule",
					"enabled":       true,
					"action":        "accept",
					"protocol":      "all",
					"bidirectional": true,
					"sources":       []string{"group-all"},
					"destinations":  []string{"group-all"},
					"ports":         []string{},
					"port_ranges":   []any{},
				},
			},
		},
	}
	writeJSON(w, policies)
}

// serveNBCreatePolicy records the created policy and returns it with ID "created-policy-id".
func serveNBCreatePolicy(w http.ResponseWriter, r *http.Request, state *nbTestState) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	state.createdPolicies = append(state.createdPolicies, body)
	// Return the policy with a server-assigned ID and rule IDs.
	rules, _ := body["rules"].([]any)
	if rules == nil {
		rules = []any{}
	}
	// Assign IDs to each rule for the response.
	for i, r := range rules {
		if rMap, ok := r.(map[string]any); ok {
			rMap["id"] = "rule-id-" + string(rune('a'+i))
			rules[i] = rMap
		}
	}
	resp := map[string]any{
		"id":      "created-policy-id",
		"name":    body["name"],
		"enabled": body["enabled"],
		"rules":   rules,
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, resp)
}

// serveNBPolicyByID returns a policy by ID.
// If the ID is "created-policy-id", returns the deny-all policy.
func serveNBPolicyByID(w http.ResponseWriter, policyID string, state *nbTestState) {
	if policyID == "created-policy-id" && len(state.createdPolicies) > 0 {
		// Return the most recently created policy.
		last := state.createdPolicies[len(state.createdPolicies)-1]
		rules, _ := last["rules"].([]any)
		// Normalize rules by adding IDs (server-assigned).
		for i, rItem := range rules {
			if rMap, ok := rItem.(map[string]any); ok {
				rMap["id"] = "rule-id-" + string(rune('a'+i))
				rules[i] = rMap
			}
		}
		resp := map[string]any{
			"id":      "created-policy-id",
			"name":    last["name"],
			"enabled": last["enabled"],
			"rules":   rules,
		}
		writeJSON(w, resp)
		return
	}
	http.Error(w, "policy not found", http.StatusNotFound)
}

// serveNBSetupKeys serves one active setup key.
func serveNBSetupKeys(w http.ResponseWriter) {
	keys := []map[string]any{
		{
			"id":          "key-1",
			"key":         "nbk_test_key_value",
			"type":        "one-off",
			"expires":     "2026-12-31T00:00:00Z",
			"used":        false,
			"revoked":     false,
			"usage_limit": 1,
			"auto_groups": []string{"group-all"},
		},
	}
	writeJSON(w, keys)
}

// serveNBCreateSetupKey returns a newly created setup key.
func serveNBCreateSetupKey(w http.ResponseWriter) {
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{
		"id":          "key-new",
		"key":         "nbk_new_key_value",
		"type":        "one-off",
		"expires":     "2026-12-31T00:00:00Z",
		"used":        false,
		"revoked":     false,
		"usage_limit": 1,
		"auto_groups": []string{},
	})
}

// writeJSON encodes v as JSON and writes it to w.
func writeJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

// ── Tests ──────────────────────────────────────────────────────────────────

// TestNetBird_doRequest_AuthorizationHeader verifies that doRequest sends the
// correct Authorization: Token header (never Bearer) — T-13-02-05.
func TestNetBird_doRequest_AuthorizationHeader(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test_api_key")

	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)

	cfg := netbirdCfg(srv.URL)
	b, err := backend.New(cfg, shell.NewMockRunner())
	require.NoError(t, err)

	// Trigger a request to the server (Status calls GET /api/peers).
	_, err = b.Status(context.Background())
	require.NoError(t, err)

	// Assert Authorization header uses "Token" not "Bearer".
	require.NotEmpty(t, state.capturedAuthHdr, "expected at least one Authorization header")
	for _, hdr := range state.capturedAuthHdr {
		assert.Contains(t, hdr, "Token ", "Authorization header must use Token scheme")
		assert.NotContains(t, hdr, "Bearer ", "Authorization header must NOT use Bearer scheme")
		assert.Contains(t, hdr, "nbp_test_api_key", "Authorization header must contain the API key")
	}
}

// TestNetBird_EnsureGroup covers three cases:
//   - group exists → returns existing ID
//   - group absent → creates new group, returns new ID
//   - name=="All" → returns error (reserved system group guard)
func TestNetBird_EnsureGroup(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test")

	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	b, err := backend.New(cfg, shell.NewMockRunner())
	require.NoError(t, err)

	// Type-assert to ACLManager to get NewACLEditor.
	acl, ok := b.(backend.ACLManager)
	require.True(t, ok, "netbirdAdapter must implement ACLManager")

	// Use NewACLEditor to get a netbirdEditor.
	editor, err := acl.NewACLEditor(nil)
	require.NoError(t, err)

	// Group editor must implement NetBirdEditor.
	nbEditor, ok := editor.(interface {
		EnsureGroup(ctx context.Context, name string) (string, error)
		FindSystemGroup(ctx context.Context, name string) (string, error)
	})
	require.True(t, ok, "netbirdEditor must expose EnsureGroup and FindSystemGroup")

	t.Run("group_exists_returns_existing_id", func(t *testing.T) {
		id, err := nbEditor.EnsureGroup(context.Background(), "dev")
		require.NoError(t, err)
		assert.Equal(t, "group-dev", id)
	})

	t.Run("group_absent_creates_new", func(t *testing.T) {
		id, err := nbEditor.EnsureGroup(context.Background(), "staging")
		require.NoError(t, err)
		assert.Equal(t, "group-new-staging", id)
	})

	t.Run("name_All_returns_error", func(t *testing.T) {
		_, err := nbEditor.EnsureGroup(context.Background(), "All")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "All")
	})
}

// TestNetBird_FindSystemGroup verifies:
//   - issued=="system" match returns correct ID
//   - no matching system group returns error
func TestNetBird_FindSystemGroup(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test")

	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	b, err := backend.New(cfg, shell.NewMockRunner())
	require.NoError(t, err)

	acl, ok := b.(backend.ACLManager)
	require.True(t, ok)
	editor, err := acl.NewACLEditor(nil)
	require.NoError(t, err)

	nbEditor, ok := editor.(interface {
		FindSystemGroup(ctx context.Context, name string) (string, error)
	})
	require.True(t, ok, "netbirdEditor must expose FindSystemGroup")

	t.Run("system_group_found", func(t *testing.T) {
		id, err := nbEditor.FindSystemGroup(context.Background(), "All")
		require.NoError(t, err)
		assert.Equal(t, "group-all", id)
	})

	t.Run("system_group_not_found_returns_error", func(t *testing.T) {
		_, err := nbEditor.FindSystemGroup(context.Background(), "NonExistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// TestNetBird_PushDenyAllBaseline verifies the full orchestration:
//   - DELETE called for the allow-all policy
//   - POST called with deny-all policy body
//   - GET called to validate the created policy
func TestNetBird_PushDenyAllBaseline(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test")

	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	b, err := backend.New(cfg, shell.NewMockRunner())
	require.NoError(t, err)

	acl, ok := b.(backend.ACLManager)
	require.True(t, ok)
	editor, err := acl.NewACLEditor(nil)
	require.NoError(t, err)

	nbEditor, ok := editor.(interface {
		PushDenyAllBaseline(ctx context.Context) error
	})
	require.True(t, ok, "netbirdEditor must expose PushDenyAllBaseline")

	err = nbEditor.PushDenyAllBaseline(context.Background())
	require.NoError(t, err)

	// Assert DELETE was called on the allow-all policy.
	assert.Contains(t, state.deletedPolicyIDs, "policy-allow-all",
		"PushDenyAllBaseline must DELETE the existing allow-all policy")

	// Assert POST was called with a deny-all policy.
	require.NotEmpty(t, state.createdPolicies, "PushDenyAllBaseline must POST a deny-all policy")
	created := state.createdPolicies[len(state.createdPolicies)-1]
	assert.Equal(t, "abysslink-deny-all", created["name"])
	rules, ok := created["rules"].([]any)
	require.True(t, ok)
	require.Len(t, rules, 1)
	rule, ok := rules[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "drop", rule["action"])
}

// TestNetBird_Validate covers three sub-cases:
//   - success: identical rules pass validation
//   - rule count mismatch: returns error with counts
//   - content mismatch: action changed returns error
func TestNetBird_Validate(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test")

	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	b, err := backend.New(cfg, shell.NewMockRunner())
	require.NoError(t, err)

	acl, ok := b.(backend.ACLManager)
	require.True(t, ok)
	editor, err := acl.NewACLEditor(nil)
	require.NoError(t, err)

	nbEditor, ok := editor.(interface {
		PushDenyAllBaseline(ctx context.Context) error
		Validate(ctx context.Context, policyID string, intent []backend.NBPolicyRule) error
	})
	require.True(t, ok, "netbirdEditor must expose Validate")

	// First push a deny-all baseline so we have a created-policy-id to validate against.
	require.NoError(t, nbEditor.PushDenyAllBaseline(context.Background()))
	require.NotEmpty(t, state.createdPolicies)

	t.Run("success_identical_rules", func(t *testing.T) {
		// The mock returns the same rules we pushed, so Validate should pass.
		intent := []backend.NBPolicyRule{
			{
				Enabled:       true,
				Action:        "drop",
				Protocol:      "all",
				Bidirectional: true,
				Sources:       []string{"group-all"},
				Destinations:  []string{"group-all"},
				Ports:         []string{},
				PortRanges:    []any{},
			},
		}
		err := nbEditor.Validate(context.Background(), "created-policy-id", intent)
		require.NoError(t, err)
	})

	t.Run("rule_count_mismatch", func(t *testing.T) {
		intent := []backend.NBPolicyRule{
			{Action: "drop", Protocol: "all", Sources: []string{"group-all"}, Destinations: []string{"group-all"}},
			{Action: "accept", Protocol: "tcp", Sources: []string{"group-dev"}, Destinations: []string{"group-dev"}},
		}
		err := nbEditor.Validate(context.Background(), "created-policy-id", intent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "count mismatch")
	})

	t.Run("content_mismatch_action_changed", func(t *testing.T) {
		// The pushed policy has action="drop" but we validate against action="accept".
		intent := []backend.NBPolicyRule{
			{
				Enabled:       true,
				Action:        "accept", // wrong — server has "drop"
				Protocol:      "all",
				Bidirectional: true,
				Sources:       []string{"group-all"},
				Destinations:  []string{"group-all"},
				Ports:         []string{},
				PortRanges:    []any{},
			},
		}
		err := nbEditor.Validate(context.Background(), "created-policy-id", intent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mismatch")
	})
}

// TestNetBird_SetACL_ValidatesAfterPush tests that SetACL re-reads each pushed
// policy and enforces content equality per D-08/SC-3.  Three sub-cases:
//
//   - success: server echoes back the exact rules → no error
//   - dropped_rule: GET returns one fewer rule than POSTed → error (FAIL)
//   - content_mismatch: GET returns rules with altered action → error (FAIL)
func TestNetBird_SetACL_ValidatesAfterPush(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test")

	// Helper: build a minimal httptest.Server whose GET /api/policies/{id}
	// returns the supplied policyByIDResp JSON (already JSON-encoded).
	// POST /api/policies echoes back an assigned ID "p1".
	makeSrv := func(t *testing.T, policyByIDJSON []byte) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/api/policies":
				// Decode the request so we can echo back with an assigned ID.
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				body["id"] = "p1"
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(body)
			case r.Method == http.MethodGet && r.URL.Path == "/api/policies/p1":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(policyByIDJSON)
			default:
				http.NotFound(w, r)
			}
		}))
	}

	// The policy JSON we will push via SetACL.
	pushedPolicy := `[{"name":"allow-ssh","enabled":true,"rules":[{"name":"ssh","enabled":true,"action":"accept","protocol":"tcp","bidirectional":false,"sources":["grp-phone"],"destinations":["grp-laptop"],"ports":["22"],"port_ranges":[]}]}]`

	// exactEcho: GET /api/policies/p1 returns the same rule that was POSTed.
	exactEchoResp, _ := json.Marshal(map[string]any{
		"id":      "p1",
		"name":    "allow-ssh",
		"enabled": true,
		"rules": []map[string]any{
			{
				"id": "r1", "name": "ssh", "enabled": true,
				"action": "accept", "protocol": "tcp", "bidirectional": false,
				"sources":      []string{"grp-phone"},
				"destinations": []string{"grp-laptop"},
				"ports":        []string{"22"},
				"port_ranges":  []any{},
			},
		},
	})

	// droppedRule: GET returns zero rules (server silently dropped the rule).
	droppedRuleResp, _ := json.Marshal(map[string]any{
		"id": "p1", "name": "allow-ssh", "enabled": true,
		"rules": []any{},
	})

	// contentMismatch: GET returns same rule count but action altered to "drop".
	contentMismatchResp, _ := json.Marshal(map[string]any{
		"id":      "p1",
		"name":    "allow-ssh",
		"enabled": true,
		"rules": []map[string]any{
			{
				"id": "r1", "name": "ssh", "enabled": true,
				"action":   "drop", // wrong — was "accept" in intent
				"protocol": "tcp", "bidirectional": false,
				"sources":      []string{"grp-phone"},
				"destinations": []string{"grp-laptop"},
				"ports":        []string{"22"},
				"port_ranges":  []any{},
			},
		},
	})

	t.Run("success_exact_echo", func(t *testing.T) {
		srv := makeSrv(t, exactEchoResp)
		defer srv.Close()
		cfg := netbirdCfg(srv.URL)
		b, err := backend.New(cfg, shell.NewMockRunner())
		require.NoError(t, err)
		acl, ok := b.(backend.ACLManager)
		require.True(t, ok)
		err = acl.SetACL(context.Background(), []byte(pushedPolicy), "")
		require.NoError(t, err, "SetACL must succeed when server echoes back the exact rules")
	})

	t.Run("dropped_rule_is_fail", func(t *testing.T) {
		srv := makeSrv(t, droppedRuleResp)
		defer srv.Close()
		cfg := netbirdCfg(srv.URL)
		b, err := backend.New(cfg, shell.NewMockRunner())
		require.NoError(t, err)
		acl, ok := b.(backend.ACLManager)
		require.True(t, ok)
		err = acl.SetACL(context.Background(), []byte(pushedPolicy), "")
		require.Error(t, err, "SetACL must return error when server drops a rule (count mismatch)")
		assert.Contains(t, err.Error(), "count mismatch",
			"error message must indicate a rule count mismatch")
	})

	t.Run("content_mismatch_is_fail", func(t *testing.T) {
		srv := makeSrv(t, contentMismatchResp)
		defer srv.Close()
		cfg := netbirdCfg(srv.URL)
		b, err := backend.New(cfg, shell.NewMockRunner())
		require.NoError(t, err)
		acl, ok := b.(backend.ACLManager)
		require.True(t, ok)
		err = acl.SetACL(context.Background(), []byte(pushedPolicy), "")
		require.Error(t, err, "SetACL must return error when server returns altered rule content")
		assert.Contains(t, err.Error(), "mismatch",
			"error message must indicate a content mismatch")
	})
}

// TestNetBird_Up_EnvInjection verifies that Up():
//   - drives the `netbird` agent binary with --management-url (NET-05: NetBird
//     does not speak the Tailscale coordination protocol)
//   - injects the setup key via NB_SETUP_KEY env (never argv)
//   - calls PushDenyAllBaseline via netbird editor
func TestNetBird_Up_EnvInjection(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test_key")
	t.Setenv("ABYSSLINK_NB_SETUP_KEY", "nbk_setup_key")

	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	// MockRunner is scripted to succeed for `netbird up`.
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: "", ExitCode: 0},
	})

	b, err := backend.New(cfg, runner)
	require.NoError(t, err)

	err = b.Up(context.Background(), backend.UpOpts{})
	require.NoError(t, err)

	// Assert the netbird agent binary was driven (NET-05) and NB_SETUP_KEY env
	// was injected and NEVER on argv.
	calls := runner.RecordedCalls()
	require.Len(t, calls, 1, "expected exactly one shell call for netbird up")
	nbUp := calls[0]

	assert.Equal(t, "netbird", nbUp.Name,
		"Up() must drive the netbird agent binary, not tailscale (NET-05)")
	assert.Contains(t, nbUp.Args, "up")
	assert.Contains(t, nbUp.Args, "--management-url",
		"Up() must pass --management-url to the netbird agent (NET-05)")
	assert.NotContains(t, nbUp.Args, "--login-server",
		"--login-server is a tailscale flag; netbird uses --management-url (NET-05)")
	require.Contains(t, nbUp.Env, "NB_SETUP_KEY",
		"NB_SETUP_KEY must be injected via env, not argv")
	assert.Equal(t, "nbk_setup_key", nbUp.Env["NB_SETUP_KEY"],
		"NB_SETUP_KEY env value must match ABYSSLINK_NB_SETUP_KEY")
	for _, arg := range nbUp.Args {
		assert.NotContains(t, arg, "nbk_setup_key",
			"setup key must NOT appear in argv (T-13-02-02)")
	}

	// Assert PushDenyAllBaseline was called (there should be a POST to /api/policies).
	assert.NotEmpty(t, state.createdPolicies,
		"Up() must call PushDenyAllBaseline which POSTs to /api/policies")
}

// TestNetBird_Up_NonZeroExit is the NET-03 regression: a non-zero `netbird up`
// exit (which ExecRunner reports as (Result{ExitCode:N}, nil)) MUST fail Up()
// — and in particular MUST NOT proceed to push the deny-all policy against a
// peer that never enrolled.
func TestNetBird_Up_NonZeroExit(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test_key")
	t.Setenv("ABYSSLINK_NB_SETUP_KEY", "nbk_setup_key")

	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 1, Stderr: "Error: connect: connection refused"},
	})

	b, err := backend.New(cfg, runner)
	require.NoError(t, err)

	err = b.Up(context.Background(), backend.UpOpts{})
	require.Error(t, err, "Up() must fail when netbird up exits non-zero (NET-03)")
	assert.Contains(t, err.Error(), "exited 1")
	assert.Contains(t, err.Error(), "connection refused",
		"error must surface the trimmed stderr for diagnosis")
	assert.Empty(t, state.createdPolicies,
		"a failed enrollment must NOT push the deny-all policy (NET-03)")
}

// TestNetBird_Down drives `netbird down` (NET-05) and fails on non-zero exit (NET-03).
func TestNetBird_Down(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test_key")
	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	t.Run("success", func(t *testing.T) {
		runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
		b, err := backend.New(cfg, runner)
		require.NoError(t, err)
		require.NoError(t, b.Down(context.Background()))

		calls := runner.RecordedCalls()
		require.Len(t, calls, 1)
		assert.Equal(t, "netbird", calls[0].Name, "Down() must drive the netbird agent binary (NET-05)")
		assert.Equal(t, []string{"down"}, calls[0].Args)
	})

	t.Run("non_zero_exit_is_error", func(t *testing.T) {
		runner := shell.NewMockRunner(shell.Call{
			Result: shell.Result{ExitCode: 1, Stderr: "daemon not running"},
		})
		b, err := backend.New(cfg, runner)
		require.NoError(t, err)
		err = b.Down(context.Background())
		require.Error(t, err, "Down() must fail when netbird down exits non-zero (NET-03)")
		assert.Contains(t, err.Error(), "daemon not running")
	})
}

// TestNetBird_Set_Unsupported verifies Set() fails honest for requested
// settings (the netbird agent has no runtime settings mutation, NET-05) and
// is a no-op success when nothing is requested.
func TestNetBird_Set_Unsupported(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test_key")
	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)
	cfg := netbirdCfg(srv.URL)

	runner := shell.NewMockRunner() // any shell call would error: Set must not shell out
	b, err := backend.New(cfg, runner)
	require.NoError(t, err)

	require.NoError(t, b.Set(context.Background(), backend.SetOpts{}),
		"Set() with no requested changes is a no-op success")

	err = b.Set(context.Background(), backend.SetOpts{Hostname: "new-name"})
	require.Error(t, err, "Set() must report unsupported for requested settings")
	require.ErrorIs(t, err, backend.ErrUnsupported)
	assert.Empty(t, runner.RecordedCalls(), "Set() must never shell out to tailscale (NET-05)")
}

// TestNetBird_LocalPeerIdentification is the NET-07 regression: IP() and
// Hostname() must return THIS machine's peer (matched via tailnet.hostname),
// not the first entry of the account-wide peer list, and must error clearly
// when the local peer is not in the list.
func TestNetBird_LocalPeerIdentification(t *testing.T) {
	t.Setenv("ABYSSLINK_NB_API_KEY", "nbp_test_key")
	state := &nbTestState{}
	srv := newNetBirdMockServer(t, state)

	t.Run("matches_local_peer_not_first", func(t *testing.T) {
		// The mock serves peer-1 "test-laptop" first and peer-2 "test-phone"
		// second; configuring the phone's name must return the phone's data.
		cfg := netbirdCfg(srv.URL)
		cfg.Tailnet.Hostname = "test-phone"
		b, err := backend.New(cfg, shell.NewMockRunner())
		require.NoError(t, err)

		ip, err := b.IP(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "100.64.0.2", ip, "IP() must return the LOCAL peer's address (NET-07)")

		name, err := b.Hostname(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "test-phone", name)
	})

	t.Run("local_peer_not_found_is_error", func(t *testing.T) {
		cfg := netbirdCfg(srv.URL)
		cfg.Tailnet.Hostname = "machine-not-enrolled-anywhere"
		b, err := backend.New(cfg, shell.NewMockRunner())
		require.NoError(t, err)

		_, err = b.IP(context.Background())
		require.Error(t, err, "IP() must error when the local peer is absent (NET-07)")
		assert.Contains(t, err.Error(), "local peer not found")

		_, err = b.Hostname(context.Background())
		require.Error(t, err, "Hostname() must error when the local peer is absent (NET-07)")
	})
}
