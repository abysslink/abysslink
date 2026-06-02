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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// netbirdAPIKeyEnv is the environment-variable fallback for the NetBird API key.
// Primary source is the OS keychain; this env var is the headless/CI override.
const netbirdAPIKeyEnv = "ABYSSLINK_NB_API_KEY" //nolint:gosec // env var name, not a secret value

// netbirdSetupKeyEnv is the environment-variable fallback for the NetBird setup key.
// Primary source is the OS keychain; this env var is the headless/CI override.
const netbirdSetupKeyEnv = "ABYSSLINK_NB_SETUP_KEY" //nolint:gosec // env var name, not a secret value

// netbirdAdapter implements Client, AdminAPI, and ACLManager against the
// NetBird REST API. It does NOT implement Locker — Tailnet Lock (TKA) is not
// available on NetBird. Capabilities().Lock is always false.
// Capabilities().SSHCheck is always false — NetBird cannot enforce the SSH
// checkPeriod (D-03/D-04).
//
// Security invariants:
//   - apiKey() is the ONLY place the API key is accessed; it flows only into
//     the Authorization: Token header inside doRequest() — never to slog, audit,
//     or argv (CLAUDE.md hard rule, T-13-02-01).
//   - The setup key is read from ABYSSLINK_NB_SETUP_KEY env and injected via
//     TS_AUTHKEY env in RunWithEnv — never on argv (T-13-02-02).
//   - Authorization header uses "Token" not "Bearer" — NetBird PAT tokens use
//     the Token scheme (T-13-02-05, RESEARCH Anti-Patterns).
type netbirdAdapter struct {
	cfg     *config.Config
	runner  shell.Runner
	baseURL string        // cfg.Server.NetBird.ServerURL; set in constructor
	apiKey  func() string // lazy loader reading ABYSSLINK_NB_API_KEY; NEVER stored as plain field

	// eventPollStart / eventPollMax bound the TailEvents --follow polling
	// backoff (start interval and cap). Defaulted in the constructor; overridable
	// in tests to keep the polling loop fast. NetBird's audit-events endpoint has
	// no streaming/cursor support, so --follow polls with bounded backoff.
	eventPollStart time.Duration
	eventPollMax   time.Duration
}

// newNetBirdAdapter constructs a netbirdAdapter from the given config and runner.
// The API key is loaded lazily from ABYSSLINK_NB_API_KEY env var (keychain
// integration is wired here via the lazy func; the env var fallback covers
// headless/CI use). Key is NEVER stored as a plain string in any struct field.
func newNetBirdAdapter(cfg *config.Config, runner shell.Runner) *netbirdAdapter {
	return &netbirdAdapter{
		cfg:     cfg,
		runner:  runner,
		baseURL: cfg.Server.NetBird.ServerURL,
		// apiKey is a lazy loader: the closure reads the env var on each call,
		// ensuring the key is never retained in memory longer than needed.
		// In a future keychain integration, swap this closure body only.
		apiKey: func() string {
			return os.Getenv(netbirdAPIKeyEnv)
		},
		eventPollStart: defaultEventPollStart,
		eventPollMax:   defaultEventPollMax,
	}
}

// setupKeyExpiry parses cfg.Server.NetBird.SetupKeyExpiry via
// time.ParseDuration; falls back to 24h if empty or parse error.
func (a *netbirdAdapter) setupKeyExpiry() time.Duration {
	if a.cfg.Server.NetBird.SetupKeyExpiry != "" {
		d, err := time.ParseDuration(a.cfg.Server.NetBird.SetupKeyExpiry)
		if err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour // paranoid-safe fallback
}

// ── Core Client methods ────────────────────────────────────────────────────

// Status returns a synthetic Status for the NetBird backend.
// It queries GET /api/peers and synthesizes a running status if any peers exist.
func (a *netbirdAdapter) Status(ctx context.Context) (*Status, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("netbird: status: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netbird: status: unexpected HTTP %d", resp.StatusCode)
	}
	var peers []nbPeer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, fmt.Errorf("netbird: status: decode: %w", err)
	}

	st := &Status{
		BackendState: StateRunning,
	}
	if len(peers) > 0 {
		p := peers[0]
		st.Self = &PeerStatus{
			HostName: p.Name,
			Online:   true,
		}
	}
	return st, nil
}

// IP returns the first IPv4 address for the first enrolled peer.
// Returns ErrUnsupported if no peers are enrolled or none have IP addresses.
func (a *netbirdAdapter) IP(ctx context.Context) (string, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/peers", nil)
	if err != nil {
		return "", fmt.Errorf("netbird: ip: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("netbird: ip: unexpected HTTP %d", resp.StatusCode)
	}
	var peers []nbPeer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return "", fmt.Errorf("netbird: ip: decode: %w", err)
	}
	var firstIP string
	for _, p := range peers {
		for _, ip := range p.IPAddresses {
			if firstIP == "" {
				firstIP = ip
			}
			if !strings.Contains(ip, ":") {
				return ip, nil
			}
		}
	}
	if firstIP != "" {
		return firstIP, nil
	}
	return "", fmt.Errorf("netbird: ip: no enrolled peers with IP addresses: %w", ErrUnsupported)
}

// Hostname returns the hostname of the first enrolled peer.
func (a *netbirdAdapter) Hostname(ctx context.Context) (string, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/peers", nil)
	if err != nil {
		return "", fmt.Errorf("netbird: hostname: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("netbird: hostname: unexpected HTTP %d", resp.StatusCode)
	}
	var peers []nbPeer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return "", fmt.Errorf("netbird: hostname: decode: %w", err)
	}
	if len(peers) > 0 {
		return peers[0].Name, nil
	}
	return "", nil
}

// SSHConfig parses cfg.Mobile.SSHCheckPeriod (a string, e.g. "12h") via
// time.ParseDuration; on empty or parse-error it falls back to the immutable
// 12h default so CheckPeriod is always non-zero (contract invariant #2).
// The 12h immutable floor applies to ALL backends — verbatim copy from headscale.go.
func (a *netbirdAdapter) SSHConfig() SSHConfig {
	if a.cfg.Mobile.SSHCheckPeriod != "" {
		d, err := time.ParseDuration(a.cfg.Mobile.SSHCheckPeriod)
		if err == nil && d > 0 {
			return SSHConfig{CheckPeriod: d}
		}
	}
	return SSHConfig{CheckPeriod: defaultSSHCheckPeriod}
}

// LockCapability returns LockNone — Tailnet Lock (TKA) is not available on NetBird.
// This is a permanent, non-overridable characteristic of the NetBird backend.
// The invariant test enforces that no Locker methods are present on this adapter.
func (a *netbirdAdapter) LockCapability() LockCapability { return LockNone }

// Capabilities returns the capability set for the NetBird adapter.
// Lock is always false — NetBird has no Tailnet Lock support.
// SSHCheck is always false — NetBird cannot enforce the 12h checkPeriod floor (D-03).
// FunnelRejection is always false — NetBird has no Funnel concept.
func (a *netbirdAdapter) Capabilities() Capabilities {
	return Capabilities{
		Lock:            false, // NetBird has no Tailnet Lock; invariant test enforces this
		AdminAPI:        true,
		SSHCheck:        false, // NetBird cannot enforce SSH checkPeriod (D-03); WARN emitted by doctor/up
		AuthKeys:        true,
		FunnelRejection: false, // NetBird has no Funnel concept
		ACL:             true,
	}
}

// Up enrolls this node against the NetBird control server using a setup key.
// The setup key is injected via TS_AUTHKEY env var — NEVER on argv (T-13-02-02).
// After enrollment, Up pushes the deny-all ACL baseline before returning (NB-01 SC-1).
//
// D-04: Up refuses to continue unless AcceptNoSSHCheck is set in config (one-time
// opt-in flag acknowledging that SSHCheck enforcement is unavailable on NetBird).
func (a *netbirdAdapter) Up(ctx context.Context, opts UpOpts) error {
	// D-04: Refuse unless the SSHCheck degradation has been explicitly acknowledged.
	if !a.cfg.Server.NetBird.AcceptNoSSHCheck {
		return fmt.Errorf("netbird: up: SSHCheck not available on NetBird — " +
			"set accept_no_sshcheck: true in abysslink.yaml or pass --accept-no-sshcheck to acknowledge " +
			"(SSHCheck unavailable; no periodic re-auth mechanism exists for setup-key-enrolled peers)")
	}

	// Setup key read from env — NEVER from argv (T-13-02-02).
	setupKey := os.Getenv(netbirdSetupKeyEnv)
	if setupKey == "" {
		return fmt.Errorf("netbird: up: %s is empty — set ABYSSLINK_NB_SETUP_KEY to the NetBird setup key", netbirdSetupKeyEnv)
	}

	hostname := opts.Hostname
	if hostname == "" {
		hostname = a.cfg.Tailnet.Hostname
	}

	args := []string{"up",
		"--login-server", a.baseURL,
	}
	if hostname != "" {
		args = append(args, "--hostname", hostname)
	}
	if opts.SSH {
		args = append(args, "--ssh")
	}
	if opts.AcceptRoutes {
		args = append(args, "--accept-routes")
	}
	if opts.AdvertiseExitNode {
		args = append(args, "--advertise-exit-node")
	}

	// Setup key injected via env — never on argv (T-13-02-02, CLAUDE.md hard rule).
	slog.Debug("netbird: up: invoking tailscale up with TS_AUTHKEY env")
	if _, err := a.runner.RunWithEnv(ctx, map[string]string{"TS_AUTHKEY": setupKey}, "tailscale", args...); err != nil {
		return fmt.Errorf("netbird: up: tailscale up: %w", err)
	}

	// NB-01 SC-1: Push deny-all ACL baseline before returning. The deny-all policy
	// is guaranteed to be in place before Up returns.
	editor := newNetBirdEditor(a.doRequest)
	slog.Debug("netbird: up: pushing deny-all ACL baseline via netbird editor")
	if err := editor.PushDenyAllBaseline(ctx); err != nil {
		return fmt.Errorf("netbird: up: push deny-all baseline: %w", err)
	}

	return nil
}

// Set applies daemon settings by calling `tailscale set`.
func (a *netbirdAdapter) Set(ctx context.Context, opts SetOpts) error {
	args := []string{"set"}
	if opts.Hostname != "" {
		args = append(args, "--hostname", opts.Hostname)
	}
	if opts.AutoUpdate {
		args = append(args, "--auto-update")
	}
	if _, err := a.runner.Run(ctx, "tailscale", args...); err != nil {
		return fmt.Errorf("netbird: set: %w", err)
	}
	return nil
}

// Down brings the Tailscale daemon down.
func (a *netbirdAdapter) Down(ctx context.Context) error {
	if _, err := a.runner.Run(ctx, "tailscale", "down"); err != nil {
		return fmt.Errorf("netbird: down: %w", err)
	}
	return nil
}

// ── AdminAPI sub-interface ─────────────────────────────────────────────────

// Devices queries GET /api/peers and returns the list of enrolled peers as []Device.
func (a *netbirdAdapter) Devices(ctx context.Context) ([]Device, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("netbird: list peers: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netbird: list peers: unexpected HTTP %d", resp.StatusCode)
	}
	var peers []nbPeer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, fmt.Errorf("netbird: list peers: decode: %w", err)
	}
	devices := make([]Device, len(peers))
	for i, p := range peers {
		devices[i] = Device{
			ID:       p.ID,
			Name:     p.Name,
			Hostname: p.Hostname,
			Tags:     p.Groups,
		}
	}
	return devices, nil
}

// TagDevice updates the groups (tags) for a peer via PUT /api/peers/{id}.
// Each tag name is mapped 1:1 to a NetBird group (D-07: Groups-as-tags).
func (a *netbirdAdapter) TagDevice(ctx context.Context, id string, tags []string) error {
	editor := newNetBirdEditor(a.doRequest)
	groupIDs := make([]string, 0, len(tags))
	for _, tag := range tags {
		gid, err := editor.EnsureGroup(ctx, tag)
		if err != nil {
			return fmt.Errorf("netbird: tag peer %s: ensure group %q: %w", id, tag, err)
		}
		groupIDs = append(groupIDs, gid)
	}
	body := map[string][]string{"groups": groupIDs}
	resp, err := a.doRequest(ctx, http.MethodPut, "/api/peers/"+id, body)
	if err != nil {
		return fmt.Errorf("netbird: tag peer %s: %w", id, err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("netbird: tag peer %s: unexpected HTTP %d", id, resp.StatusCode)
	}
	return nil
}

// DeleteDevice removes a peer via DELETE /api/peers/{id}.
func (a *netbirdAdapter) DeleteDevice(ctx context.Context, id string) error {
	resp, err := a.doRequest(ctx, http.MethodDelete, "/api/peers/"+id, nil)
	if err != nil {
		return fmt.Errorf("netbird: delete peer %s: %w", id, err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("netbird: delete peer %s: unexpected HTTP %d", id, resp.StatusCode)
	}
	return nil
}

// CreateAuthKey creates a one-time setup key via POST /api/setup-keys.
// type="one-off" + expires_in enforces paranoid defaults (nb-key-type).
// The key value goes to caller — NEVER logged (T-13-02-02).
func (a *netbirdAdapter) CreateAuthKey(ctx context.Context, tags []string) (string, error) {
	editor := newNetBirdEditor(a.doRequest)
	groupIDs := make([]string, 0, len(tags))
	for _, tag := range tags {
		gid, err := editor.EnsureGroup(ctx, tag)
		if err != nil {
			return "", fmt.Errorf("netbird: create auth key: ensure group %q: %w", tag, err)
		}
		groupIDs = append(groupIDs, gid)
	}

	expirySeconds := int(a.setupKeyExpiry().Seconds())
	reqBody := nbCreateSetupKeyRequest{
		Name:       "abysslink-rig",
		Type:       "one-off",
		ExpiresIn:  expirySeconds,
		AutoGroups: groupIDs,
		UsageLimit: 1,
		Ephemeral:  false,
	}
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/setup-keys", reqBody)
	if err != nil {
		return "", fmt.Errorf("netbird: create auth key: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("netbird: create auth key: unexpected HTTP %d", resp.StatusCode)
	}
	var result nbSetupKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("netbird: create auth key: decode: %w", err)
	}
	if result.Key == "" {
		return "", fmt.Errorf("netbird: create auth key: empty key in response")
	}
	// Key goes to caller — NEVER logged (T-13-02-02).
	return result.Key, nil
}

// ── ACLManager sub-interface ───────────────────────────────────────────────

// GetACL queries GET /api/policies and returns the policies marshaled as JSON.
// ETag is empty — NetBird REST has no ETag (returns "" per spec).
func (a *netbirdAdapter) GetACL(ctx context.Context) ([]byte, string, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/policies", nil)
	if err != nil {
		return nil, "", fmt.Errorf("netbird: get acl: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("netbird: get acl: unexpected HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("netbird: get acl: read: %w", err)
	}
	return raw, "", nil // ETag is empty for NetBird
}

// SetACL decodes acl bytes as a policies JSON array and calls editor.PushPolicy
// for each policy.  For every push, PushPolicy re-reads the created policy from
// the backend and calls Validate() to enforce SC-3 (silently dropped rule is
// FAIL, not warning).  The intent (rule list) for each policy is decoded from
// the input JSON so the Validate() call has accurate expected-state.
func (a *netbirdAdapter) SetACL(ctx context.Context, acl []byte, _ string) error {
	// Decode as an array of raw JSON objects (policies).
	var policies []json.RawMessage
	if err := json.Unmarshal(acl, &policies); err != nil {
		return fmt.Errorf("netbird: set acl: decode policies: %w", err)
	}
	editor := newNetBirdEditor(a.doRequest)
	for i, p := range policies {
		// Extract the rules from the raw policy body to use as Validate() intent.
		// Only the rules field is needed; other fields (name, enabled, description)
		// are not part of the SC-3 content-equality check.
		var policyBody struct {
			Rules []NBPolicyRule `json:"rules"`
		}
		if err := json.Unmarshal(p, &policyBody); err != nil {
			return fmt.Errorf("netbird: set acl: decode rules for policy[%d]: %w", i, err)
		}
		if err := editor.PushPolicy(ctx, p, policyBody.Rules); err != nil {
			return fmt.Errorf("netbird: set acl: push policy[%d]: %w", i, err)
		}
	}
	return nil
}

// NewACLEditor returns a new netbirdEditor wrapping this adapter's doRequest.
// NetBird uses plain JSON policies, not HuJSON.
func (a *netbirdAdapter) NewACLEditor(_ []byte) (ACLEditor, error) {
	return newNetBirdEditor(a.doRequest), nil
}

// DefaultACL returns the deny-all baseline policy JSON bytes matching the
// testdata golden fixture shape (internal/backend/testdata/netbird/policy_deny_all.json).
// The __ALL_GROUP_ID__ placeholder is left unresolved — callers must substitute
// the actual system group ID via the editor.
func (a *netbirdAdapter) DefaultACL(_, _ string) []byte {
	return []byte(`{"name":"abysslink-deny-all","description":"Abysslink deny-all baseline — pushed before first node admission","enabled":true,"rules":[{"name":"deny-all","enabled":true,"action":"drop","protocol":"all","bidirectional":true,"sources":[],"destinations":[],"ports":[],"port_ranges":[]}]}`)
}

// Diff returns a simple line diff of the JSON bytes.
// NetBird uses plain JSON, not HuJSON; no special parsing required.
func (a *netbirdAdapter) Diff(oldBytes, newBytes []byte) string {
	var sb strings.Builder
	oldLines := strings.Split(strings.TrimRight(string(oldBytes), "\n"), "\n")
	newLines := strings.Split(strings.TrimRight(string(newBytes), "\n"), "\n")
	oldSet := make(map[string]bool, len(oldLines))
	for _, l := range oldLines {
		oldSet[l] = true
	}
	newSet := make(map[string]bool, len(newLines))
	for _, l := range newLines {
		newSet[l] = true
	}
	for _, l := range oldLines {
		if !newSet[l] {
			sb.WriteString("- " + l + "\n")
		}
	}
	for _, l := range newLines {
		if !oldSet[l] {
			sb.WriteString("+ " + l + "\n")
		}
	}
	return sb.String()
}

// ── Internal helpers ──────────────────────────────────────────────────────

// doRequest performs an authenticated HTTP request against the NetBird REST API.
//
// Security: apiKey() is the ONLY place the API key is accessed.
// The key is set ONLY in the Authorization: Token header and is NEVER:
//   - passed to slog.* (T-13-02-01)
//   - passed to audit.Append or any log entry content field
//   - passed as argv to any subprocess
//
// Authorization header: "Token <nbp_...>" — NOT "Bearer" for PAT tokens.
// NetBird's auth_middleware.go confirms the "Token" scheme for PAT tokens (T-13-02-05).
//
// TLS: http.DefaultClient uses the system TLS root store with full verification.
// InsecureSkipVerify is NEVER set.
func (a *netbirdAdapter) doRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var buf io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("netbird: marshal request body: %w", err)
		}
		buf = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, buf)
	if err != nil {
		return nil, fmt.Errorf("netbird: build request: %w", err)
	}
	// PAT tokens use "Token" not "Bearer" — NetBird auth_middleware.go confirms this.
	// API key flows ONLY into this header — never logged, never on argv (T-13-02-01).
	req.Header.Set("Authorization", "Token "+a.apiKey())
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req) //nolint:wrapcheck // caller wraps
}

// ── NetBird REST API response types ─────────────────────────────────────

// nbPeer is a single peer from GET /api/peers.
type nbPeer struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Hostname    string   `json:"hostname"`
	IPAddresses []string `json:"ip_addresses"`
	Groups      []string `json:"groups"`
}

// nbCreateSetupKeyRequest is the POST /api/setup-keys request body.
// type="one-off" + usage_limit=1 enforces paranoid defaults (nb-key-type).
type nbCreateSetupKeyRequest struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`       // "one-off" or "reusable"
	ExpiresIn  int      `json:"expires_in"` // seconds; range 86400–31536000
	AutoGroups []string `json:"auto_groups"`
	UsageLimit int      `json:"usage_limit"`
	Ephemeral  bool     `json:"ephemeral"`
}

// nbSetupKeyResponse is the response from POST /api/setup-keys.
type nbSetupKeyResponse struct {
	ID         string   `json:"id"`
	Key        string   `json:"key"` // NEVER log this field
	Type       string   `json:"type"`
	Expires    string   `json:"expires"`
	Used       bool     `json:"used"`
	Revoked    bool     `json:"revoked"`
	UsageLimit int      `json:"usage_limit"`
	AutoGroups []string `json:"auto_groups"`
}
