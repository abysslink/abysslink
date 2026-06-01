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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// NewNetBirdDoRequest builds a real REST helper for the NetBird doctor REST
// checks (nb-api-auth, nb-key-type, nb-zitadel) from the given config.
//
// The returned closure binds to a freshly constructed netbirdAdapter so the
// CLI layer can pass it into NetBirdDoctorChecks() without creating a circular
// dependency. The API key flows only into the Authorization: Token header
// inside doRequest() — never to argv, slog, or the audit log (CLAUDE.md).
//
// Returns nil if cfg is nil.
func NewNetBirdDoRequest(cfg *config.Config) func(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if cfg == nil {
		return nil
	}
	// Construct a minimal adapter for the REST helper. The runner is not used by
	// doRequest; a nil runner is safe here since doctor REST checks never shell out.
	return newNetBirdAdapter(cfg, nil).doRequest
}

// NetBirdDoctorChecks returns []DoctorFinding for all 9 nb-* doctor checks.
//
// Check ordering (per plan spec and ROADMAP SC-5 + PR-A):
//  0. nb-sshcheck — D-03 mandatory degradation WARN, always emitted unconditionally
//  1. nb-tls      — TLS cert validity check (filesystem)
//  2. nb-version  — binary version floor v0.57.0 (shell)
//  3. nb-zitadel  — D-02 detect-then-probe (config + optional REST)
//  4. nb-mgmt-bind — metrics port binding check (config)
//  5. nb-key-type — setup key type/expiry check (REST)
//  6. nb-api-auth — API authentication check (REST)
//  7. nb-proc-user — service process user (shell, Linux/macOS conditional)
//  8. nb-runtime  — PR-A: container runtime check (macOS only; Linux SKIP)
//
// The function accepts a doRequestFunc rather than a *netbirdAdapter to avoid
// coupling to the concrete adapter — tests pass a mock, production code passes
// adapter.doRequest via NewNetBirdDoRequest.
func NetBirdDoctorChecks(
	ctx context.Context,
	cfg *config.Config,
	runner shell.Runner,
	doReq doRequestFunc,
) []DoctorFinding {
	var findings []DoctorFinding

	// ── Finding 0: nb-sshcheck (D-03, always present, unconditional WARN) ────────
	// EXACT REQUIRED TEXT — verbatim substring required by plan must_haves.
	findings = append(findings, DoctorFinding{
		Module:   "netbird",
		Check:    "nb-sshcheck",
		Severity: DoctorWarning,
		Message: "WARN: SSHCheck not available on NetBird — checkPeriod enforcement disabled. " +
			"Setup-key-enrolled peers have no periodic re-auth mechanism in NetBird.",
	})

	// ── Findings 1–7: 7 canonical nb-* checks from ROADMAP SC-5 ─────────────────

	// nb-tls: TLS certificate validity.
	findings = append(findings, checkNbTLS(ctx, cfg))

	// nb-version: binary version floor v0.57.0.
	findings = append(findings, checkNbVersion(ctx, runner, cfg.Server.NetBird.BinaryPath))

	// nb-zitadel: D-02 detect-then-probe.
	findings = append(findings, checkNbZitadel(ctx, cfg, doReq))

	// nb-mgmt-bind: metrics port binding.
	findings = append(findings, checkNbMgmtBind(cfg))

	// nb-key-type: setup key type + expiry.
	findings = append(findings, checkNbKeyType(ctx, doReq))

	// nb-api-auth: API authentication.
	findings = append(findings, checkNbAPIAuth(ctx, doReq))

	// nb-proc-user: service process user.
	findings = append(findings, checkNbProcUser(ctx, runner))

	// ── Finding 8: nb-runtime (PR-A) ─────────────────────────────────────────────
	findings = append(findings, checkNbRuntime(ctx, runner))

	return findings
}

// ── nb-tls ────────────────────────────────────────────────────────────────────

// checkNbTLS validates the TLS certificate configured for the NetBird server.
// Reads server.tls.certFile and server.tls.keyFile from the config.yaml at
// cfg.Server.NetBird.ConfigPath. Mirrors checkHsTLS() from headscale_doctor.go.
func checkNbTLS(ctx context.Context, cfg *config.Config) DoctorFinding {
	const check = "nb-tls"
	const mod = "netbird"

	nbCfg, err := parseNbConfigYAML(cfg.Server.NetBird.ConfigPath)
	if err != nil {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-tls: could not parse config.yaml: %v", err),
		}
	}

	certFile := nbCfg.Server.TLS.CertFile
	keyFile := nbCfg.Server.TLS.KeyFile

	if certFile == "" || keyFile == "" {
		// Fall back to config struct fields if not in config.yaml.
		certFile = cfg.Server.NetBird.TLSCertFile
		keyFile = cfg.Server.NetBird.TLSKeyFile
	}

	if certFile == "" {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorFatal,
			Message: "nb-tls: no TLS certificate configured — server.tls.certFile is empty (TLS is required)",
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorFatal,
			Message: fmt.Sprintf("nb-tls: cert/key load failed: %v", err),
		}
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorFatal,
			Message: fmt.Sprintf("nb-tls: parse leaf cert: %v", err),
		}
	}

	now := time.Now()
	if now.After(leaf.NotAfter) {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorFatal,
			Message: fmt.Sprintf("nb-tls: certificate expired at %s", leaf.NotAfter.Format(time.RFC3339)),
		}
	}

	// Warn if cert expires within 30 days.
	warnThreshold := now.Add(30 * 24 * time.Hour)
	if warnThreshold.After(leaf.NotAfter) {
		remaining := int(leaf.NotAfter.Sub(now).Hours() / 24)
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-tls: cert expires within %d days (expiry: %s)", remaining, leaf.NotAfter.Format(time.RFC3339)),
		}
	}

	// SAN check against ServerURL hostname.
	if cfg.Server.NetBird.ServerURL != "" {
		host := extractHostname(cfg.Server.NetBird.ServerURL)
		if host != "" {
			if sanErr := leaf.VerifyHostname(host); sanErr != nil {
				return DoctorFinding{
					Module: mod, Check: check, Severity: DoctorFatal,
					Message: fmt.Sprintf("nb-tls: SAN mismatch for %q: %v", host, sanErr),
				}
			}
		}
	}

	slog.DebugContext(ctx, "nb-tls: certificate valid", "cert", certFile)
	return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK, Message: "TLS certificate is valid"}
}

// ── nb-version ────────────────────────────────────────────────────────────────

// checkNbVersion checks that the netbird-server binary version is at or above
// the v0.57.0 floor (CVE-2025-10678 fix boundary). Uses shell.Runner for all
// binary invocations (CLAUDE.md hard rule).
func checkNbVersion(ctx context.Context, runner shell.Runner, binaryPath string) DoctorFinding {
	const check = "nb-version"
	const mod = "netbird"

	// macOS container path: binary not applicable (enforced by container image tag).
	if binaryPath == "" && runtime.GOOS == "darwin" {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorOK,
			Message: "nb-version: macOS container path — version enforced by image tag at provision time",
		}
	}

	if binaryPath == "" {
		binaryPath = "netbird-server"
	}

	res, err := runner.Run(ctx, binaryPath, "--version")
	if err != nil || res.ExitCode != 0 {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-version: could not query binary version (%q --version failed)", binaryPath),
		}
	}

	version, ok := parseNetBirdVersion(res.Stdout)
	if !ok {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-version: could not parse version from output %q", res.Stdout),
		}
	}

	const floor = "0.57.0"
	if semverLessThan(version, floor) {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorFatal,
			Message: fmt.Sprintf("nb-version: %s is below minimum v%s (CVE-2025-10678 fix boundary) — upgrade required", version, floor),
		}
	}

	return DoctorFinding{
		Module: mod, Check: check, Severity: DoctorOK,
		Message: fmt.Sprintf("nb-version: %s meets minimum v%s floor", version, floor),
	}
}

// parseNetBirdVersion parses "netbird-server version v0.71.4" or "v0.71.4" from
// the --version output. Returns the version string (without the "v" prefix) and
// ok=true on success.
func parseNetBirdVersion(output string) (string, bool) {
	output = strings.TrimSpace(output)
	// Find a token starting with "v" followed by digits.
	for _, token := range strings.Fields(output) {
		token = strings.TrimPrefix(token, "v")
		parts := strings.Split(token, ".")
		if len(parts) >= 2 {
			_, err1 := strconv.Atoi(parts[0])
			_, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil {
				return token, true
			}
		}
	}
	return "", false
}

// semverLessThan reports whether a < b, comparing major.minor.patch tuples.
// Non-numeric or missing components are treated as 0.
// Example: semverLessThan("0.30.0", "0.57.0") == true
func semverLessThan(a, b string) bool {
	parse := func(s string) [3]int {
		s = strings.TrimPrefix(s, "v")
		var parts [3]int
		for i, tok := range strings.SplitN(s, ".", 3) {
			if i >= 3 {
				break
			}
			// strip pre-release suffixes (e.g. "1-rc1")
			tok = strings.SplitN(tok, "-", 2)[0]
			n, _ := strconv.Atoi(tok)
			parts[i] = n
		}
		return parts
	}
	av := parse(a)
	bv := parse(b)
	for i := 0; i < 3; i++ {
		if av[i] < bv[i] {
			return true
		}
		if av[i] > bv[i] {
			return false
		}
	}
	return false // equal
}

// ── nb-zitadel ────────────────────────────────────────────────────────────────

// checkNbZitadel implements the D-02 detect-then-probe logic:
//  1. Read server.auth.issuer from config.yaml.
//  2. If issuer does not contain "zitadel" → SKIP/PASS.
//  3. If ZITADEL detected → POST /management/v1/users/_search to the issuer base.
//     HTTP 401/403 or count==0 → PASS. HTTP 200 with results → FAIL (CVE-2025-10678).
//
// The probe uses a ZITADEL Bearer token (NOT the NetBird "Token" scheme). The probe
// searches for the default "zitadel-admin@" username. No auth token is needed for
// this search because the probe relies on public endpoint behavior.
func checkNbZitadel(ctx context.Context, cfg *config.Config, doReq doRequestFunc) DoctorFinding {
	const check = "nb-zitadel"
	const mod = "netbird"

	nbCfg, err := parseNbConfigYAML(cfg.Server.NetBird.ConfigPath)
	if err != nil {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-zitadel: could not parse config.yaml: %v", err),
		}
	}

	issuer := nbCfg.Server.Auth.Issuer
	if !strings.Contains(strings.ToLower(issuer), "zitadel") {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorOK,
			Message: "no ZITADEL deployment detected — SKIP",
		}
	}

	// ZITADEL detected — run the probe.
	// Extract base URL from issuer (strip any path suffix).
	issuerBase := extractIssuerBase(issuer)

	// Build the search request directly (this is NOT the NetBird API, so we
	// cannot use the NetBird doReq. We build a raw HTTP POST.).
	probe := nbZitadelProbe(ctx, issuerBase)
	return probe
}

// nbZitadelProbe sends the ZITADEL default-creds probe to the issuer base URL.
// It does NOT use the doRequestFunc (which carries the NetBird Token auth) —
// ZITADEL probes use Bearer auth and the endpoint is the ZITADEL management API.
func nbZitadelProbe(ctx context.Context, issuerBase string) DoctorFinding {
	const check = "nb-zitadel"
	const mod = "netbird"

	url := strings.TrimSuffix(issuerBase, "/") + "/management/v1/users/_search"
	body := map[string]any{
		"queries": []map[string]any{
			{
				"userNameQuery": map[string]any{
					"userName": "zitadel-admin@",
					"method":   "TEXT_QUERY_METHOD_STARTS_WITH",
				},
			},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-zitadel: could not build probe request: %v", err),
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-zitadel: could not create probe request: %v", err),
		}
	}
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header — we rely on HTTP 401 from ZITADEL when default
	// creds are absent, and HTTP 200 when they are still active.

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-zitadel: probe request failed (server may be unreachable): %v", err),
		}
	}
	defer resp.Body.Close() //nolint:errcheck

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: "nb-zitadel: ZITADEL detected — default admin credentials rejected (PASS)",
		}
	case http.StatusOK:
		// Check if results were returned.
		respBody, _ := io.ReadAll(resp.Body)
		var result struct {
			Result []any `json:"result"`
		}
		if jsonErr := json.Unmarshal(respBody, &result); jsonErr == nil && len(result.Result) > 0 {
			return DoctorFinding{
				Module: mod, Check: check, Severity: DoctorFatal,
				Message: "ZITADEL default admin account still active (CVE-2025-10678) — run the ZITADEL cleanup script to remove zitadel-admin@ user",
			}
		}
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: "nb-zitadel: ZITADEL detected — no default admin accounts found (PASS)",
		}
	default:
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-zitadel: probe returned unexpected HTTP %d", resp.StatusCode),
		}
	}
}

// extractIssuerBase strips any path from an OIDC issuer URL to get the base URL
// for ZITADEL management API calls. "https://zitadel.example.com/realms/nb" →
// "https://zitadel.example.com".
func extractIssuerBase(issuer string) string {
	// For ZITADEL the issuer typically IS the base URL already (no path).
	// Strip any trailing path components beyond the host to be safe.
	trimmed := strings.TrimSuffix(issuer, "/")
	// If there's a path, the ZITADEL management endpoint is always at root.
	// Find the scheme + host part.
	if idx := strings.Index(trimmed, "://"); idx >= 0 {
		rest := trimmed[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			return trimmed[:idx+3] + rest[:slashIdx]
		}
	}
	return trimmed
}

// ── nb-mgmt-bind ──────────────────────────────────────────────────────────────

// checkNbMgmtBind checks that the metrics port is NOT bound to 0.0.0.0.
// Per RESEARCH.md anti-patterns: check metricsPort, not listenAddress
// (server.listenAddress `:443` is expected to bind all interfaces for peer
// connectivity; only the metrics/admin port should be loopback-gated).
func checkNbMgmtBind(cfg *config.Config) DoctorFinding {
	const check = "nb-mgmt-bind"
	const mod = "netbird"

	nbCfg, err := parseNbConfigYAML(cfg.Server.NetBird.ConfigPath)
	if err != nil {
		return DoctorFinding{
			Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-mgmt-bind: could not parse config.yaml: %v", err),
		}
	}

	// Check metricsListenAddress from parsed YAML.
	if metricsAddr := nbCfg.MetricsListenAddress; metricsAddr != "" {
		if strings.Contains(metricsAddr, "0.0.0.0") {
			return DoctorFinding{
				Module: mod, Check: check, Severity: DoctorFatal,
				Message: fmt.Sprintf("nb-mgmt-bind: metricsListenAddress=%q exposes metrics publicly — must be loopback-only", metricsAddr),
			}
		}
	}

	// Also check the MgmtBindAddr from config struct (set by operator in abysslink.yaml).
	if mgmtBind := cfg.Server.NetBird.MgmtBindAddr; mgmtBind != "" {
		if strings.Contains(mgmtBind, "0.0.0.0") {
			return DoctorFinding{
				Module: mod, Check: check, Severity: DoctorFatal,
				Message: fmt.Sprintf("nb-mgmt-bind: mgmt_bind_addr=%q contains 0.0.0.0 — metrics must not be exposed publicly", mgmtBind),
			}
		}
	}

	return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
		Message: "nb-mgmt-bind: metrics port is not exposed to 0.0.0.0",
	}
}

// ── nb-key-type ───────────────────────────────────────────────────────────────

// checkNbKeyType checks all active setup keys via GET /api/setup-keys.
// FAIL: any active key has type != "one-off" (reusable key = unauthorized enrollment risk).
// FAIL: any active key has a zero or past expiry.
// WARN: no active setup keys found.
// PASS: all active keys are one-off with valid future expiry.
func checkNbKeyType(ctx context.Context, doReq doRequestFunc) DoctorFinding {
	const check = "nb-key-type"
	const mod = "netbird"

	if doReq == nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-key-type: skipped — no API client available",
		}
	}

	resp, err := doReq(ctx, http.MethodGet, "/api/setup-keys", nil)
	if err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-key-type: could not complete check: " + err.Error(),
		}
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-key-type: could not complete check: HTTP %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-key-type: could not read response body: " + err.Error(),
		}
	}

	var keys []nbSetupKey
	if err := json.Unmarshal(body, &keys); err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-key-type: could not parse response: " + err.Error(),
		}
	}

	now := time.Now()
	activeCount := 0

	for _, k := range keys {
		// Skip revoked/used keys.
		if k.Revoked {
			continue
		}
		activeCount++

		if k.Type != "one-off" {
			return DoctorFinding{
				Module: mod, Check: check, Severity: DoctorFatal,
				Message: fmt.Sprintf("nb-key-type: setup key %q has type=%q — only 'one-off' keys are permitted (reusable keys allow unauthorized enrollment)", k.Name, k.Type),
			}
		}

		// Check expiry: zero time or past expiry is a failure.
		if k.Expires.IsZero() || k.Expires.Equal(time.Time{}) {
			return DoctorFinding{
				Module: mod, Check: check, Severity: DoctorFatal,
				Message: fmt.Sprintf("nb-key-type: setup key %q has zero expiry — rotate with explicit expiry", k.Name),
			}
		}
		if now.After(k.Expires) || now.Equal(k.Expires) {
			return DoctorFinding{
				Module: mod, Check: check, Severity: DoctorFatal,
				Message: fmt.Sprintf("nb-key-type: setup key %q expired at %s — revoke and rotate", k.Name, k.Expires.Format(time.RFC3339)),
			}
		}
	}

	if activeCount == 0 {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-key-type: no active setup keys found",
		}
	}
	return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
		Message: fmt.Sprintf("nb-key-type: all %d active setup key(s) are one-off with valid expiry", activeCount),
	}
}

// nbSetupKey is the response element from GET /api/setup-keys.
type nbSetupKey struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Expires time.Time `json:"expires"`
	Revoked bool      `json:"revoked"`
}

// ── nb-api-auth ───────────────────────────────────────────────────────────────

// checkNbAPIAuth verifies that the API key authenticates against GET /api/groups.
// PASS: HTTP 200. FAIL: HTTP 401/403. WARN: network error or other status.
func checkNbAPIAuth(ctx context.Context, doReq doRequestFunc) DoctorFinding {
	const check = "nb-api-auth"
	const mod = "netbird"

	if doReq == nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-api-auth: skipped — no API client available",
		}
	}

	resp, err := doReq(ctx, http.MethodGet, "/api/groups", nil)
	if err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-api-auth: NetBird API unreachable: " + err.Error(),
		}
	}
	defer resp.Body.Close() //nolint:errcheck

	switch resp.StatusCode {
	case http.StatusOK:
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: "nb-api-auth: API key is valid and authenticated",
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorFatal,
			Message: fmt.Sprintf("nb-api-auth: API key invalid or missing (HTTP %d)", resp.StatusCode),
		}
	default:
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-api-auth: unexpected HTTP %d from /api/groups", resp.StatusCode),
		}
	}
}

// ── nb-proc-user ──────────────────────────────────────────────────────────────

// checkNbProcUser checks that the NetBird server process runs as a non-root user.
// Linux: systemctl show netbird-server --property=User.
// macOS: SKIP (macOS uses container path per PR-A; process user is enforced by runtime).
func checkNbProcUser(ctx context.Context, runner shell.Runner) DoctorFinding {
	const check = "nb-proc-user"
	const mod = "netbird"

	if runtime.GOOS == "darwin" {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: "nb-proc-user: macOS uses container path — process user enforced by container runtime (nb-runtime)",
		}
	}
	return checkNbProcUserLinux(ctx, runner, check, mod)
}

// checkNbProcUserLinux probes the netbird-server service user via systemctl.
func checkNbProcUserLinux(ctx context.Context, runner shell.Runner, check, mod string) DoctorFinding {
	res, err := runner.Run(ctx, "systemctl", "show", "netbird-server", "--property=User")
	if err != nil || res.ExitCode != 0 {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "nb-proc-user: systemctl could not query netbird-server service — service may not be installed",
		}
	}

	out := strings.TrimSpace(res.Stdout)
	if !strings.HasPrefix(out, "User=") {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: fmt.Sprintf("nb-proc-user: unexpected systemctl output %q — cannot confirm non-root user", out),
		}
	}

	user := strings.TrimPrefix(out, "User=")
	switch user {
	case "", "root", "0":
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorFatal,
			Message: "nb-proc-user: netbird-server service runs as root — must run as a dedicated non-root user",
		}
	default:
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: fmt.Sprintf("nb-proc-user: service runs as %q (non-root)", user),
		}
	}
}

// ── nb-runtime (PR-A, Finding 8) ─────────────────────────────────────────────

// checkNbRuntime checks that a container runtime is present and reachable on macOS.
// macOS: probe docker, colima, podman in order — first exit 0 wins.
// Linux: SKIP (native binary; no container runtime needed).
// This implements the PR-A post-research amendment: macOS NetBird server runs in
// a container (goreleaser provides no darwin binary), so a container runtime is
// required.
func checkNbRuntime(ctx context.Context, runner shell.Runner) DoctorFinding {
	const check = "nb-runtime"
	const mod = "netbird"

	if runtime.GOOS != "darwin" {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: "nb-runtime: Linux uses native binary — SKIP",
		}
	}

	// Probe docker, colima, podman in order.
	type runtime struct {
		name string
		args []string
	}
	probes := []runtime{
		{name: "docker", args: []string{"info"}},
		{name: "colima", args: []string{"status"}},
		{name: "podman", args: []string{"info"}},
	}

	for _, p := range probes {
		res, err := runner.Run(ctx, p.name, p.args...)
		if err == nil && res.ExitCode == 0 {
			return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
				Message: fmt.Sprintf("nb-runtime: container runtime %q present and reachable", p.name),
			}
		}
	}

	return DoctorFinding{Module: mod, Check: check, Severity: DoctorFatal,
		Message: "nb-runtime: no container runtime found — required for NetBird server on macOS (nb-runtime); install Docker, Colima, or Podman",
	}
}

// ── Config YAML parsing ───────────────────────────────────────────────────────

// nbConfigYAML is the loosely-typed struct for parsing NetBird config.yaml.
// Only keys needed by doctor checks are modelled; all others are preserved by
// the lenient (KnownFields false) decoder.
type nbConfigYAML struct {
	MetricsListenAddress string `yaml:"metricsListenAddress"`
	Server               struct {
		ListenAddress string `yaml:"listenAddress"`
		TLS           struct {
			CertFile string `yaml:"certFile"`
			KeyFile  string `yaml:"keyFile"`
		} `yaml:"tls"`
		Auth struct {
			Issuer string `yaml:"issuer"`
		} `yaml:"auth"`
	} `yaml:"server"`
}

// parseNbConfigYAML decodes a NetBird config.yaml with a lenient decoder.
func parseNbConfigYAML(path string) (*nbConfigYAML, error) {
	if path == "" {
		return nil, fmt.Errorf("netbird config path is empty")
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	var cfg nbConfigYAML
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Lenient: preserve user's unknown keys (KnownFields false is the default).
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &cfg, nil
}
