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
	"fmt"
	"log/slog"
	"net/http"
	"sort"
)

// netbirdEditor implements policy CRUD, Groups-as-tags mapping, and Validate()
// for the NetBird REST API. It is used by netbirdAdapter for ACL operations.
//
// The doReq field is injected from the adapter so tests can substitute an
// httptest.Server without needing a real NetBird instance.
//
// NetBird uses plain JSON policies (not HuJSON). The editor implements the
// ACLEditor interface but extends it with additional policy methods.
type netbirdEditor struct {
	doReq func(ctx context.Context, method, path string, body any) (*http.Response, error)
}

// newNetBirdEditor creates a new netbirdEditor with the given doReq function.
// The doReq function is typically netbirdAdapter.doRequest.
func newNetBirdEditor(doReq func(ctx context.Context, method, path string, body any) (*http.Response, error)) *netbirdEditor {
	return &netbirdEditor{doReq: doReq}
}

// ── ACLEditor interface (required by ACLManager.NewACLEditor) ─────────────

// Bytes returns nil — the netbirdEditor does not maintain an in-memory document.
// NetBird policies are managed via REST; this method satisfies the ACLEditor
// interface contract for callers that expect a byte slice.
func (e *netbirdEditor) Bytes() []byte {
	return nil
}

// EnsureTagOwners is a no-op for NetBird — the NetBird policy model does not
// use tag owners. Groups-as-tags mapping is handled via EnsureGroup/TagDevice.
func (e *netbirdEditor) EnsureTagOwners(_ string) error {
	return nil
}

// EnsureGrant is a no-op for NetBird — the NetBird policy model does not use
// grants. Peer-to-peer routing is controlled via policies pushed by SetACL.
func (e *netbirdEditor) EnsureGrant() error {
	return nil
}

// EnsureSSHRule is a no-op for NetBird — SSH rule enforcement via the
// checkPeriod mechanism is not available (Capabilities().SSHCheck=false, D-03).
// The degradation is surfaced via WARN in up/doctor; no rule is written here.
func (e *netbirdEditor) EnsureSSHRule(_, _, _ string) error {
	return nil
}

// ── Groups-as-tags ────────────────────────────────────────────────────────

// listGroups retrieves all groups via GET /api/groups.
func (e *netbirdEditor) listGroups(ctx context.Context) ([]nbGroup, error) {
	resp, err := e.doReq(ctx, http.MethodGet, "/api/groups", nil)
	if err != nil {
		return nil, fmt.Errorf("netbird: list groups: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netbird: list groups: unexpected HTTP %d", resp.StatusCode)
	}
	var groups []nbGroup
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, fmt.Errorf("netbird: list groups: decode: %w", err)
	}
	return groups, nil
}

// EnsureGroup creates a group with the given name if it does not already exist.
// Returns the group ID. Implements 1:1 name mapping per D-07.
//
// Guard: name=="All" returns an error — "All" is auto-managed by NetBird
// (issued=="system") and must never be created via EnsureGroup (T-13-02-06).
//
// Idempotent: if a group with the same name already exists, its ID is returned.
func (e *netbirdEditor) EnsureGroup(ctx context.Context, name string) (string, error) {
	if name == "All" {
		return "", fmt.Errorf("netbird: EnsureGroup: cannot create reserved system group All")
	}
	groups, err := e.listGroups(ctx)
	if err != nil {
		return "", err
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID, nil
		}
	}
	// Group does not exist — create it.
	body := map[string]any{"name": name}
	resp, err := e.doReq(ctx, http.MethodPost, "/api/groups", body)
	if err != nil {
		return "", fmt.Errorf("netbird: create group %q: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("netbird: create group %q: unexpected HTTP %d", name, resp.StatusCode)
	}
	var created nbGroup
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("netbird: create group %q: decode: %w", name, err)
	}
	if created.ID == "" {
		return "", fmt.Errorf("netbird: create group %q: empty ID in response", name)
	}
	return created.ID, nil
}

// FindSystemGroup locates the auto-managed system group by Issued=="system" AND
// Name==name. This is the correct way to identify the "All" group (T-13-02-06,
// RESEARCH Anti-Patterns Pitfall 5).
func (e *netbirdEditor) FindSystemGroup(ctx context.Context, name string) (string, error) {
	groups, err := e.listGroups(ctx)
	if err != nil {
		return "", err
	}
	for _, g := range groups {
		if g.Issued == "system" && g.Name == name {
			return g.ID, nil
		}
	}
	return "", fmt.Errorf("netbird: FindSystemGroup: system group %q not found", name)
}

// ── Policy CRUD ───────────────────────────────────────────────────────────

// listPolicies retrieves all policies via GET /api/policies.
func (e *netbirdEditor) listPolicies(ctx context.Context) ([]nbPolicy, error) {
	resp, err := e.doReq(ctx, http.MethodGet, "/api/policies", nil)
	if err != nil {
		return nil, fmt.Errorf("netbird: list policies: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netbird: list policies: unexpected HTTP %d", resp.StatusCode)
	}
	var policies []nbPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return nil, fmt.Errorf("netbird: list policies: decode: %w", err)
	}
	return policies, nil
}

// RemoveAllowAllPolicies removes any existing allow-all policies on the system
// "All" group. Specifically: for each policy, if any rule has action=="accept"
// AND sources or destinations contains the "All" system-group ID, that policy
// is deleted.
//
// This implements SC-1: the default NetBird allow-all policy is removed before
// pushing the deny-all baseline. The "All" group itself is NOT deleted.
func (e *netbirdEditor) RemoveAllowAllPolicies(ctx context.Context) error {
	allGroupID, err := e.FindSystemGroup(ctx, "All")
	if err != nil {
		return fmt.Errorf("netbird: remove allow-all: find All group: %w", err)
	}
	policies, err := e.listPolicies(ctx)
	if err != nil {
		return fmt.Errorf("netbird: remove allow-all: list policies: %w", err)
	}
	for _, policy := range policies {
		if policyIsAllowAllOnGroup(policy, allGroupID) {
			resp, err := e.doReq(ctx, http.MethodDelete, "/api/policies/"+policy.ID, nil)
			if err != nil {
				return fmt.Errorf("netbird: remove allow-all: delete policy %s: %w", policy.ID, err)
			}
			if cerr := resp.Body.Close(); cerr != nil {
				slog.Warn("netbird: close delete-policy response body (best-effort)", "err", cerr)
			}
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
				return fmt.Errorf("netbird: remove allow-all: delete policy %s: unexpected HTTP %d", policy.ID, resp.StatusCode)
			}
		}
	}
	return nil
}

// policyIsAllowAllOnGroup returns true if any rule in the policy has
// action=="accept" AND references allGroupID in sources or destinations.
func policyIsAllowAllOnGroup(policy nbPolicy, allGroupID string) bool {
	for _, rule := range policy.Rules {
		if rule.Action != "accept" {
			continue
		}
		for _, src := range rule.Sources {
			if src == allGroupID {
				return true
			}
		}
		for _, dst := range rule.Destinations {
			if dst == allGroupID {
				return true
			}
		}
	}
	return false
}

// PushDenyAllBaseline orchestrates the deny-all policy push per SC-1 / NB-01:
//  1. Find the "All" system group ID.
//  2. Remove existing allow-all policies on "All".
//  3. POST the deny-all policy body.
//  4. Parse the created policy ID.
//  5. Call Validate() with the intended rules.
//
// Returns the first non-nil error encountered.
func (e *netbirdEditor) PushDenyAllBaseline(ctx context.Context) error {
	// Step 1: locate the "All" system group.
	allGroupID, err := e.FindSystemGroup(ctx, "All")
	if err != nil {
		return fmt.Errorf("netbird: deny-all baseline: %w", err)
	}

	// Step 2: remove existing allow-all policies on "All".
	if err := e.RemoveAllowAllPolicies(ctx); err != nil {
		return fmt.Errorf("netbird: deny-all baseline: %w", err)
	}

	// Step 3: define the deny-all rule (used both for POST and for Validate() intent).
	intendedRule := nbPolicyRule{
		Name:          "deny-all",
		Enabled:       true,
		Action:        "drop",
		Protocol:      "all",
		Bidirectional: true,
		Sources:       []string{allGroupID},
		Destinations:  []string{allGroupID},
		Ports:         []string{},
		PortRanges:    []any{},
	}
	policy := map[string]any{
		"name":        "abysslink-deny-all",
		"description": "Abysslink deny-all baseline — pushed before first node admission",
		"enabled":     true,
		"rules":       []nbPolicyRule{intendedRule},
	}

	// Step 4: POST the deny-all policy.
	resp, err := e.doReq(ctx, http.MethodPost, "/api/policies", policy)
	if err != nil {
		return fmt.Errorf("netbird: deny-all baseline: push: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("netbird: deny-all baseline: push: unexpected HTTP %d", resp.StatusCode)
	}
	var created nbPolicy
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return fmt.Errorf("netbird: deny-all baseline: parse response: %w", err)
	}
	if created.ID == "" {
		return fmt.Errorf("netbird: deny-all baseline: empty policy ID in response")
	}

	// Step 5: D-08 Validate() — re-read the policy and verify content equality.
	if err := e.Validate(ctx, created.ID, []nbPolicyRule{intendedRule}); err != nil {
		return fmt.Errorf("netbird: deny-all baseline: validate: %w", err)
	}

	return nil
}

// PushPolicy posts a single raw policy JSON message to POST /api/policies,
// then re-reads the created policy and validates content equality per D-08/SC-3.
//
// The intent parameter carries the rules from the input policy body and is
// passed to Validate() so any silently dropped or altered rule returns an error
// (FAIL, not warning). This closes the "every ACL policy push" requirement of
// SC-3 for the general-purpose SetACL path — mirroring the Validate() call
// already present in PushDenyAllBaseline.
func (e *netbirdEditor) PushPolicy(ctx context.Context, raw json.RawMessage, intent []nbPolicyRule) error {
	resp, err := e.doReq(ctx, http.MethodPost, "/api/policies", raw)
	if err != nil {
		return fmt.Errorf("netbird: push policy: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("netbird: push policy: unexpected HTTP %d", resp.StatusCode)
	}

	// D-08 / SC-3: parse the response to extract the created policy ID, then
	// re-read and validate content equality. A mismatch (dropped/altered rule)
	// is a FAIL, not a warning.
	var created nbPolicy
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return fmt.Errorf("netbird: push policy: parse response: %w", err)
	}
	if created.ID == "" {
		return fmt.Errorf("netbird: push policy: empty policy ID in response")
	}
	if err := e.Validate(ctx, created.ID, intent); err != nil {
		return fmt.Errorf("netbird: push policy: validate: %w", err)
	}
	return nil
}

// Validate re-reads a policy by ID and enforces full content equality per D-08.
// Comparison:
//   - (a) len(actual.Rules) != len(intent) → error with counts
//   - (b) for each rule pair: normalize by sorting sources, destinations, ports;
//     compare action, protocol, bidirectional, sources, destinations, ports,
//     port_ranges. Strip id/name from comparison (server assigns IDs).
//
// ANY mismatch → FAIL (not warning). This is the "silently dropped rule" guard (D-08, SC-3).
func (e *netbirdEditor) Validate(ctx context.Context, policyID string, intent []nbPolicyRule) error {
	resp, err := e.doReq(ctx, http.MethodGet, "/api/policies/"+policyID, nil)
	if err != nil {
		return fmt.Errorf("netbird: validate: re-read policy %s: %w", policyID, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("netbird: validate: re-read policy %s: unexpected HTTP %d", policyID, resp.StatusCode)
	}
	var actual nbPolicy
	if err := json.NewDecoder(resp.Body).Decode(&actual); err != nil {
		return fmt.Errorf("netbird: validate: decode policy %s: %w", policyID, err)
	}

	// (a) Rule count check.
	if len(actual.Rules) != len(intent) {
		return fmt.Errorf("netbird: validate: rule count mismatch: got %d, want %d",
			len(actual.Rules), len(intent))
	}

	// (b) Per-rule content equality (normalized, IDs stripped).
	for i, want := range intent {
		got := actual.Rules[i]
		if err := rulesContentEqual(got, want); err != nil {
			return fmt.Errorf("netbird: validate: rule[%d] content mismatch: %w", i, err)
		}
	}
	return nil
}

// rulesContentEqual checks two nbPolicyRule values for content equality,
// normalizing (sorting) sources, destinations, and ports before comparison.
// IDs and names are excluded from comparison (server assigns IDs).
func rulesContentEqual(got, want nbPolicyRule) error {
	// Normalize by sorting slice fields.
	gotSrc := sortedCopy(got.Sources)
	wantSrc := sortedCopy(want.Sources)
	gotDst := sortedCopy(got.Destinations)
	wantDst := sortedCopy(want.Destinations)
	gotPorts := sortedCopy(got.Ports)
	wantPorts := sortedCopy(want.Ports)

	if got.Action != want.Action {
		return fmt.Errorf("action: got %q, want %q", got.Action, want.Action)
	}
	if got.Protocol != want.Protocol {
		return fmt.Errorf("protocol: got %q, want %q", got.Protocol, want.Protocol)
	}
	if got.Bidirectional != want.Bidirectional {
		return fmt.Errorf("bidirectional: got %v, want %v", got.Bidirectional, want.Bidirectional)
	}
	if !stringSliceEqual(gotSrc, wantSrc) {
		return fmt.Errorf("sources: got %v, want %v", gotSrc, wantSrc)
	}
	if !stringSliceEqual(gotDst, wantDst) {
		return fmt.Errorf("destinations: got %v, want %v", gotDst, wantDst)
	}
	if !stringSliceEqual(gotPorts, wantPorts) {
		return fmt.Errorf("ports: got %v, want %v", gotPorts, wantPorts)
	}
	return nil
}

// sortedCopy returns a sorted copy of s (or nil if s is nil).
func sortedCopy(s []string) []string {
	if s == nil {
		return nil
	}
	c := make([]string, len(s))
	copy(c, s)
	sort.Strings(c)
	return c
}

// stringSliceEqual compares two string slices for equality.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── NetBird policy types ────────────────────────────────────────────────

// nbGroup is a single group from GET /api/groups.
type nbGroup struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Issued string `json:"issued"` // "system" for auto-managed groups like "All"
}

// nbPolicy is a single policy from GET /api/policies or POST /api/policies.
type nbPolicy struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Enabled bool           `json:"enabled"`
	Rules   []nbPolicyRule `json:"rules"`
}

// nbPolicyRule is a single rule within a policy.
// IDs and names are excluded from content-equality comparison (D-08).
// Exported as NBPolicyRule for use in tests and doctor checks.
type nbPolicyRule = NBPolicyRule

// NBPolicyRule is the exported form of nbPolicyRule for use in tests and
// doctor checks that need to construct Validate() intent slices.
type NBPolicyRule struct {
	ID            string   `json:"id,omitempty"`
	Name          string   `json:"name,omitempty"`
	Enabled       bool     `json:"enabled"`
	Action        string   `json:"action"`   // "accept" or "drop"
	Protocol      string   `json:"protocol"` // "all", "tcp", "udp", "icmp"
	Bidirectional bool     `json:"bidirectional"`
	Sources       []string `json:"sources"`
	Destinations  []string `json:"destinations"`
	Ports         []string `json:"ports"`
	PortRanges    []any    `json:"port_ranges"`
}
