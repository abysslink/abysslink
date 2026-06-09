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
	"github.com/abysslink/abysslink/internal/tailscale"
)

// headscaleAPIKeyEnv is the environment-variable fallback for the Headscale API key.
// Primary source is the OS keychain; this env var is the headless/CI override.
const headscaleAPIKeyEnv = "ABYSSLINK_HS_API_KEY" //nolint:gosec // env var name, not a secret value

// headscalePreAuthKeyEnv is the environment-variable fallback for the Headscale pre-auth key.
const headscalePreAuthKeyEnv = "ABYSSLINK_HS_PREAUTHKEY" //nolint:gosec // env var name, not a secret value

// headscaleAdapter implements Client, AdminAPI, and ACLManager against the
// Headscale gRPC-gateway REST API. It does NOT implement Locker — Tailnet Lock
// (TKA) is not available on Headscale. Capabilities().Lock is always false.
//
// Security invariants:
//   - apiKey() is the ONLY place the API key is accessed; it flows only into
//     the Authorization: Bearer header inside doRequest() — never to slog, audit,
//     or argv (CLAUDE.md hard rule, D-10).
//   - The pre-auth key is injected via TS_AUTHKEY env in RunWithEnv — never on
//     argv (CLAUDE.md hard rule, D-11).
type headscaleAdapter struct {
	cfg     *config.Config
	runner  shell.Runner
	baseURL string        // cfg.Server.Headscale.ServerURL; set in constructor
	apiKey  func() string // lazy keychain loader; NEVER stored as a plain string field
}

// newHeadscaleAdapter constructs a headscaleAdapter from the given config and runner.
// The API key is loaded lazily from ABYSSLINK_HS_API_KEY env var (keychain integration
// is wired here via the lazy func; the env var fallback covers headless/CI use).
// Key is NEVER stored as a plain string in any struct field.
func newHeadscaleAdapter(cfg *config.Config, runner shell.Runner) *headscaleAdapter {
	return &headscaleAdapter{
		cfg:     cfg,
		runner:  runner,
		baseURL: cfg.Server.Headscale.ServerURL,
		// apiKey is a lazy loader: the closure reads the env var on each call,
		// ensuring the key is never retained in memory longer than needed.
		// In a future keychain integration, swap this closure body only.
		apiKey: func() string {
			return os.Getenv(headscaleAPIKeyEnv)
		},
	}
}

// preAuthKeyExpiry parses cfg.Server.Headscale.PreAuthKeyExpiry via
// time.ParseDuration; falls back to 1h if empty or parse error (D-11).
func (a *headscaleAdapter) preAuthKeyExpiry() time.Duration {
	if a.cfg.Server.Headscale.PreAuthKeyExpiry != "" {
		d, err := time.ParseDuration(a.cfg.Server.Headscale.PreAuthKeyExpiry)
		if err == nil && d > 0 {
			return d
		}
	}
	return time.Hour // paranoid-safe fallback per D-11
}

// ── Core Client methods ────────────────────────────────────────────────────

// listNodes queries GET /api/v1/node and decodes the account-wide node list.
// op names the calling operation for error wrapping.
func (a *headscaleAdapter) listNodes(ctx context.Context, op string) ([]hsNode, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/v1/node", nil)
	if err != nil {
		return nil, fmt.Errorf("headscale: %s: %w", op, err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("headscale: %s: unexpected HTTP %d", op, resp.StatusCode)
	}
	data, err := readLimited(resp.Body, maxBackendBody)
	if err != nil {
		return nil, fmt.Errorf("headscale: %s: read response: %w", op, err)
	}
	var result hsNodesResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("headscale: %s: decode: %w", op, err)
	}
	return result.Nodes, nil
}

// localNode identifies THIS machine in the account-wide node list by matching
// the configured tailnet hostname and the OS hostname against each node's
// name/givenName (NET-07). Returns a clear error when the local node is not
// found — never an arbitrary other machine's entry.
func (a *headscaleAdapter) localNode(nodes []hsNode) (*hsNode, error) {
	candidates := localNodeCandidates(a.cfg.Tailnet.Hostname)
	for i := range nodes {
		if matchesLocalNode(candidates, nodes[i].Name, nodes[i].GivenName) {
			return &nodes[i], nil
		}
	}
	return nil, fmt.Errorf(
		"headscale: local node not found among %d enrolled node(s) (looked for %v) — "+
			"set tailnet.hostname in abysslink.yaml to this machine's enrolled name, or enroll first (abysslink up)",
		len(nodes), candidates)
}

// Status returns a synthetic Status for the Headscale backend.
// It queries GET /api/v1/node and synthesizes a running status. Self is set
// only when THIS machine is identified in the node list (NET-07) — never the
// arbitrary first entry of the account-wide list.
func (a *headscaleAdapter) Status(ctx context.Context) (*Status, error) {
	nodes, err := a.listNodes(ctx, "status")
	if err != nil {
		return nil, err
	}

	st := &Status{
		BackendState: StateRunning,
	}
	// Honest absence: when the local node cannot be identified, Self stays nil
	// rather than reporting another machine's identity (NET-07).
	if n, lErr := a.localNode(nodes); lErr == nil {
		st.Self = &PeerStatus{
			HostName: n.Name,
			Online:   n.Online,
		}
	}
	return st, nil
}

// IP returns the IP address of THIS machine's node (NET-07). It returns an
// error when the local node cannot be identified in the account-wide list, and
// ErrUnsupported when the local node has no IP addresses yet.
func (a *headscaleAdapter) IP(ctx context.Context) (string, error) {
	nodes, err := a.listNodes(ctx, "ip")
	if err != nil {
		return "", err
	}
	n, err := a.localNode(nodes)
	if err != nil {
		return "", fmt.Errorf("headscale: ip: %w", err)
	}
	// Select the IPv4 address explicitly rather than IPAddresses[0]: Headscale's
	// ordering is not guaranteed, and downstream consumers follow the tailscale
	// adapter convention of an IPv4 address. Fall back to the first address only
	// if no IPv4 entry is present (IPv6-only node).
	var firstIP string
	for _, ip := range n.IPAddresses {
		if firstIP == "" {
			firstIP = ip
		}
		if !strings.Contains(ip, ":") {
			return ip, nil
		}
	}
	if firstIP != "" {
		return firstIP, nil
	}
	return "", fmt.Errorf("headscale: ip: local node %q has no IP addresses: %w", n.Name, ErrUnsupported)
}

// Hostname returns the control-plane name of THIS machine's node (NET-07).
// It returns an error when the local node cannot be identified.
func (a *headscaleAdapter) Hostname(ctx context.Context) (string, error) {
	nodes, err := a.listNodes(ctx, "hostname")
	if err != nil {
		return "", err
	}
	n, err := a.localNode(nodes)
	if err != nil {
		return "", fmt.Errorf("headscale: hostname: %w", err)
	}
	return n.Name, nil
}

// SSHConfig parses cfg.Mobile.SSHCheckPeriod (a string, e.g. "12h") via
// time.ParseDuration; on empty or parse-error it falls back to the immutable
// 12h default so CheckPeriod is always non-zero (contract invariant #2).
// The 12h immutable floor applies to ALL backends — verbatim copy from tailscale.go.
func (a *headscaleAdapter) SSHConfig() SSHConfig {
	if a.cfg.Mobile.SSHCheckPeriod != "" {
		d, err := time.ParseDuration(a.cfg.Mobile.SSHCheckPeriod)
		if err == nil && d > 0 {
			return SSHConfig{CheckPeriod: d}
		}
	}
	return SSHConfig{CheckPeriod: defaultSSHCheckPeriod}
}

// LockCapability returns LockNone — Tailnet Lock (TKA) is not available on Headscale.
// This is a permanent, non-overridable characteristic of the Headscale backend.
// The invariant test enforces that no Locker methods are present on this adapter.
func (a *headscaleAdapter) LockCapability() LockCapability { return LockNone }

// Capabilities returns the capability set for the Headscale adapter.
// Lock is always false — Headscale has no Tailnet Lock support.
// FunnelRejection is always false — Headscale has no Funnel concept.
func (a *headscaleAdapter) Capabilities() Capabilities {
	return Capabilities{
		Lock:            false, // Headscale has no Tailnet Lock; lockstep invariant test enforces this
		AdminAPI:        true,
		SSHCheck:        true,
		AuthKeys:        true,
		FunnelRejection: false, // Headscale has no Funnel concept
		ACL:             true,
	}
}

// Up enrolls this node against the Headscale control server using a pre-auth key.
// The pre-auth key is injected via TS_AUTHKEY env var — NEVER on argv (D-11).
// After enrollment, Up pushes the deny-all ACL baseline before returning (HS-01 SC-1).
func (a *headscaleAdapter) Up(ctx context.Context, opts UpOpts) error {
	preAuthKey := os.Getenv(headscalePreAuthKeyEnv)
	if preAuthKey == "" {
		return fmt.Errorf("headscale: up: %s is empty — mint a pre-auth key first (server headscale init --apply)", headscalePreAuthKeyEnv)
	}

	hostname := opts.Hostname
	if hostname == "" {
		hostname = a.cfg.Tailnet.Hostname
	}

	// D-03: defense-in-depth re-check before passing hostname to argv.
	if hostname != "" {
		if err := config.ValidateHostname(hostname); err != nil {
			return fmt.Errorf("headscale: up: %w", err)
		}
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

	// Key injected via env — never on argv (D-11, CLAUDE.md hard rule).
	slog.Debug("headscale: up: invoking tailscale up with TS_AUTHKEY env")
	res, err := a.runner.RunWithEnv(ctx, map[string]string{"TS_AUTHKEY": preAuthKey}, "tailscale", args...)
	if err != nil {
		return fmt.Errorf("headscale: up: tailscale up: %w", err)
	}
	// NET-03: shell.ExecRunner returns (Result{ExitCode:N}, nil) on a non-zero
	// exit — err alone does NOT signal enrollment failure. Without this check a
	// failed `tailscale up` would be treated as success and the deny-all ACL
	// pushed against a node that never enrolled.
	if res.ExitCode != 0 {
		return fmt.Errorf("headscale: up: tailscale up exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	// HS-01: Push deny-all ACL baseline before returning. The deny-all policy is
	// guaranteed to be in place before Up returns; a brief window exists between
	// enrollment (the tailscale up above) and this policy push during which the
	// node is admitted under Headscale's current/empty policy. Do not remove this
	// push — it is the safeguard that closes that window before control returns.
	denyAll := a.DefaultACL("", "")
	slog.Debug("headscale: up: pushing deny-all ACL baseline")
	if err := a.SetACL(ctx, denyAll, ""); err != nil {
		return fmt.Errorf("headscale: up: push deny-all ACL: %w", err)
	}

	return nil
}

// Set applies daemon settings by calling `tailscale set`.
func (a *headscaleAdapter) Set(ctx context.Context, opts SetOpts) error {
	args := []string{"set"}
	if opts.Hostname != "" {
		args = append(args, "--hostname", opts.Hostname)
	}
	if opts.AutoUpdate {
		args = append(args, "--auto-update")
	}
	res, err := a.runner.Run(ctx, "tailscale", args...)
	if err != nil {
		return fmt.Errorf("headscale: set: %w", err)
	}
	if res.ExitCode != 0 { // NET-03: non-zero exit is failure, not success
		return fmt.Errorf("headscale: set: tailscale set exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// Down brings the Tailscale daemon down.
func (a *headscaleAdapter) Down(ctx context.Context) error {
	res, err := a.runner.Run(ctx, "tailscale", "down")
	if err != nil {
		return fmt.Errorf("headscale: down: %w", err)
	}
	if res.ExitCode != 0 { // NET-03: non-zero exit is failure, not success
		return fmt.Errorf("headscale: down: tailscale down exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// ── AdminAPI sub-interface ─────────────────────────────────────────────────

// Devices queries GET /api/v1/node and returns the list of enrolled nodes
// as []Device.
func (a *headscaleAdapter) Devices(ctx context.Context) ([]Device, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/v1/node", nil)
	if err != nil {
		return nil, fmt.Errorf("headscale: list nodes: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("headscale: list nodes: unexpected HTTP %d", resp.StatusCode)
	}
	data, err := readLimited(resp.Body, maxBackendBody)
	if err != nil {
		return nil, fmt.Errorf("headscale: list nodes: read response: %w", err)
	}
	var result hsNodesResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("headscale: list nodes: decode: %w", err)
	}
	devices := make([]Device, len(result.Nodes))
	for i, n := range result.Nodes {
		devices[i] = Device{
			ID:       n.ID,
			Name:     n.Name,
			Hostname: n.GivenName,
			Tags:     n.ValidTags,
		}
	}
	return devices, nil
}

// TagDevice sets the ACL tags for a node via POST /api/v1/node/{id}/tags.
func (a *headscaleAdapter) TagDevice(ctx context.Context, id string, tags []string) error {
	body := map[string][]string{"tags": tags}
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/v1/node/"+id+"/tags", body)
	if err != nil {
		return fmt.Errorf("headscale: tag node %s: %w", id, err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("headscale: tag node %s: unexpected HTTP %d", id, resp.StatusCode)
	}
	return nil
}

// DeleteDevice removes a node via DELETE /api/v1/node/{id}.
func (a *headscaleAdapter) DeleteDevice(ctx context.Context, id string) error {
	resp, err := a.doRequest(ctx, http.MethodDelete, "/api/v1/node/"+id, nil)
	if err != nil {
		return fmt.Errorf("headscale: delete node %s: %w", id, err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("headscale: delete node %s: unexpected HTTP %d", id, resp.StatusCode)
	}
	return nil
}

// CreateAuthKey creates a pre-authorized key via POST /api/v1/preauthkey.
// The Expiration field is ALWAYS set explicitly (time.Now().Add(preAuthKeyExpiry)) —
// never zero — per issue #1579 prevention (D-11, T-12-02-06).
func (a *headscaleAdapter) CreateAuthKey(ctx context.Context, tags []string) (string, error) {
	expiry := time.Now().Add(a.preAuthKeyExpiry())
	reqBody := hsCreatePreAuthKeyRequest{
		User:       a.cfg.Server.Headscale.User,
		Reusable:   false,
		Ephemeral:  true,
		Expiration: expiry,
		ACLTags:    tags,
	}
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/v1/preauthkey", reqBody)
	if err != nil {
		return "", fmt.Errorf("headscale: create auth key: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("headscale: create auth key: unexpected HTTP %d", resp.StatusCode)
	}
	data, err := readLimited(resp.Body, maxBackendBody)
	if err != nil {
		return "", fmt.Errorf("headscale: create auth key: read response: %w", err)
	}
	var result hsCreatePreAuthKeyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("headscale: create auth key: decode: %w", err)
	}
	if result.PreAuthKey.Key == "" {
		return "", fmt.Errorf("headscale: create auth key: empty key in response")
	}
	return result.PreAuthKey.Key, nil
}

// ── ACLManager sub-interface ───────────────────────────────────────────────

// GetACL queries GET /api/v1/policy and returns the HuJSON policy bytes and ETag.
func (a *headscaleAdapter) GetACL(ctx context.Context) ([]byte, string, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/v1/policy", nil)
	if err != nil {
		return nil, "", fmt.Errorf("headscale: get acl: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("headscale: get acl: unexpected HTTP %d", resp.StatusCode)
	}
	data, err := readLimited(resp.Body, maxBackendBody)
	if err != nil {
		return nil, "", fmt.Errorf("headscale: get acl: read response: %w", err)
	}
	var result hsPolicyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, "", fmt.Errorf("headscale: get acl: decode: %w", err)
	}
	etag := resp.Header.Get("ETag")
	return []byte(result.Policy), etag, nil
}

// SetACL pushes a new ACL policy via PUT /api/v1/policy with HuJSON body.
func (a *headscaleAdapter) SetACL(ctx context.Context, acl []byte, _ string) error {
	// Headscale's PUT /api/v1/policy accepts {"policy": "<huJSON string>"}
	body := map[string]string{"policy": string(acl)}
	resp, err := a.doRequest(ctx, http.MethodPut, "/api/v1/policy", body)
	if err != nil {
		return fmt.Errorf("headscale: set acl: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("headscale: set acl: unexpected HTTP %d", resp.StatusCode)
	}
	return nil
}

// NewACLEditor delegates to tailscale.NewACLEditor (HuJSON reuse per RESEARCH.md
// "Don't Hand-Roll"). The HuJSON format is backend-neutral.
func (a *headscaleAdapter) NewACLEditor(raw []byte) (ACLEditor, error) {
	return tailscale.NewACLEditor(raw)
}

// DefaultACL delegates to tailscale.DefaultACL (same HuJSON deny-all baseline).
// For Headscale, this produces the deny-all baseline pushed during Up() enrollment.
func (a *headscaleAdapter) DefaultACL(owner, sshUser string) []byte {
	return tailscale.DefaultACL(owner, sshUser)
}

// Diff delegates to tailscale.Diff (same HuJSON diff logic).
func (a *headscaleAdapter) Diff(oldBytes, newBytes []byte) string {
	return tailscale.Diff(oldBytes, newBytes)
}

// ── Internal helpers ──────────────────────────────────────────────────────

// doRequest performs an authenticated HTTP request against the Headscale REST API.
//
// Security: apiKey() is the ONLY place the API key is accessed.
// The key is set ONLY in the Authorization: Bearer header and is NEVER:
//   - passed to slog.* (T-12-02-01)
//   - passed to audit.Append or any log entry content field
//   - passed as argv to any subprocess
//
// TLS: backendHTTPClient uses the system TLS root store with full verification.
// InsecureSkipVerify is NEVER set (T-12-02-04). The TLS cert gate is enforced
// at init time (Wave 4), not here. The shared client carries a 30s timeout so
// a hung control plane cannot stall callers forever (NET-06).
func (a *headscaleAdapter) doRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var buf io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("headscale: marshal request body: %w", err)
		}
		buf = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, buf)
	if err != nil {
		return nil, fmt.Errorf("headscale: build request: %w", err)
	}
	// API key flows ONLY into this header — never logged, never on argv (D-10).
	req.Header.Set("Authorization", "Bearer "+a.apiKey())
	req.Header.Set("Content-Type", "application/json")
	return backendHTTPClient.Do(req) //nolint:wrapcheck // caller wraps
}

// ── Headscale REST API response types ─────────────────────────────────────

// hsNode is a single node from GET /api/v1/node.
type hsNode struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	GivenName   string   `json:"givenName"`
	Online      bool     `json:"online"`
	IPAddresses []string `json:"ipAddresses"`
	ValidTags   []string `json:"validTags"`
}

// hsNodesResponse wraps the list of nodes from GET /api/v1/node.
type hsNodesResponse struct {
	Nodes []hsNode `json:"nodes"`
}

// hsCreatePreAuthKeyRequest is the POST /api/v1/preauthkey request body.
// Expiration is ALWAYS set (never zero) — see issue #1579 prevention (T-12-02-06).
type hsCreatePreAuthKeyRequest struct {
	User       string    `json:"user"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Expiration time.Time `json:"expiration"` // MUST be non-zero (D-11)
	ACLTags    []string  `json:"aclTags"`
}

// hsPreAuthKey is the pre-auth key structure in POST /api/v1/preauthkey response.
type hsPreAuthKey struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	ACLTags    []string  `json:"aclTags"`
}

// hsCreatePreAuthKeyResponse wraps the response from POST /api/v1/preauthkey.
type hsCreatePreAuthKeyResponse struct {
	PreAuthKey hsPreAuthKey `json:"preAuthKey"`
}

// hsPolicyResponse is the response body from GET /api/v1/policy.
type hsPolicyResponse struct {
	Policy    string `json:"policy"`
	UpdatedAt string `json:"updatedAt"`
}
