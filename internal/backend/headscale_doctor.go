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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// ── Doctor Finding types ───────────────────────────────────────────────────────
//
// These mirror modules.Severity and modules.Finding. They are defined here rather
// than imported from internal/modules to avoid an import cycle:
// internal/modules/deps.go already imports internal/backend (for backend.Client),
// so internal/backend cannot import internal/modules without creating a cycle.
//
// The internal/cli layer (which imports both) converts DoctorFinding→modules.Finding
// for display via cmd_doctor.go.

// DoctorSeverity classifies the result of a doctor check.
type DoctorSeverity int

const (
	// DoctorOK indicates a passing check.
	DoctorOK DoctorSeverity = 0
	// DoctorWarning indicates a degraded but non-blocking condition.
	DoctorWarning DoctorSeverity = 1
	// DoctorFatal indicates a blocking failure.
	DoctorFatal DoctorSeverity = 2
)

// DoctorFinding is a single check result from HeadscaleDoctorChecks.
// It is structurally identical to modules.Finding and is converted to
// modules.Finding by the CLI layer.
type DoctorFinding struct {
	Module   string
	Check    string
	Severity DoctorSeverity
	Message  string
}

// doRequestFunc is the type for the HTTP helper passed to HeadscaleDoctorChecks.
// It mirrors the signature of headscaleAdapter.doRequest so the adapter can pass
// its method directly and tests can pass a mock.
type doRequestFunc func(ctx context.Context, method, path string, body any) (*http.Response, error)

// NewHeadscaleDoRequest builds a real REST helper for the Headscale doctor REST
// checks (hs-api-auth, hs-key-expiry) from the given config and runner. The CLI
// layer passes the result into HeadscaleDoctorChecks so those checks execute
// against the live control server instead of being skipped. The returned closure
// is the headscaleAdapter.doRequest method bound to a freshly-constructed adapter;
// the API key flows only into the Authorization: Bearer header, never to argv or
// logs (D-10). Returns nil only if cfg is nil.
func NewHeadscaleDoRequest(cfg *config.Config, runner shell.Runner) func(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if cfg == nil {
		return nil
	}
	return newHeadscaleAdapter(cfg, runner).doRequest
}

// ValidateHeadscaleTLS is the single source of truth for TLS validation used by
// both the hs-tls doctor check (called from HeadscaleDoctorChecks) and by the
// Plan 12-04 init command (called from internal/cli — cli→backend direction).
//
// BYO mode (cfg.Server.Headscale.ACME==false):
//   - Loads cert+key via crypto/tls.LoadX509KeyPair (returns error on failure)
//   - Parses leaf cert via crypto/x509.ParseCertificate
//   - Returns error "certificate expired" if NotAfter < now
//   - Returns error "cert expires within N days" if NotAfter < now+CertExpiryWarnDays
//   - Returns error if leaf.VerifyHostname(fqdn) fails (SAN mismatch)
//   - Returns error if key file has group/world-readable perms (mode & 0o077 != 0)
//
// ACME mode (cfg.Server.Headscale.ACME==true):
//   - Returns error if the FQDN cannot be derived from cfg.Server.Headscale.ServerURL
//
// Returns nil on success. The hs-tls check in HeadscaleDoctorChecks calls this
// function and converts the returned error to a Finding (WARN if error contains
// "within", FAIL otherwise).
func ValidateHeadscaleTLS(ctx context.Context, cfg *config.Config) error {
	hs := cfg.Server.Headscale

	// CR-04: defense-in-depth scheme gate. server_url MUST be https:// so the
	// Bearer API key and minted pre-auth key are never sent over cleartext HTTP.
	// config.Validate enforces this too; re-checking here covers callers that
	// reach the REST path through ValidateHeadscaleTLS without a full re-validate.
	if !strings.HasPrefix(hs.ServerURL, "https://") {
		return fmt.Errorf("headscale tls: server_url %q must use https:// — plaintext http would leak the API key and pre-auth key", hs.ServerURL)
	}

	if hs.ACME {
		return validateACMETLS(hs)
	}
	return validateBYOTLS(ctx, hs)
}

// validateACMETLS validates TLS configuration for ACME mode.
func validateACMETLS(hs config.HeadscaleServer) error {
	hostname := extractHostname(hs.ServerURL)
	if hostname == "" {
		return fmt.Errorf("headscale tls: ACME mode requires a non-empty server_url from which the hostname can be derived")
	}
	return nil
}

// validateBYOTLS validates TLS configuration for BYO (bring-your-own) cert mode.
func validateBYOTLS(_ context.Context, hs config.HeadscaleServer) error {
	certPath := hs.TLSCertPath
	keyPath := hs.TLSKeyPath

	// Load the cert+key pair.
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("headscale tls: cert/key load failed: %w", err)
	}

	// Parse the leaf certificate.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("headscale tls: parse leaf cert: %w", err)
	}

	now := time.Now()

	// Check expiry.
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("headscale tls: certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}

	// Check warning threshold (returns "within" in the error string so hs-tls
	// wraps it as SeverityWarning instead of SeverityFatal).
	warnDays := hs.CertExpiryWarnDays
	if warnDays <= 0 {
		warnDays = 30
	}
	warnThreshold := now.Add(time.Duration(warnDays) * 24 * time.Hour)
	if warnThreshold.After(leaf.NotAfter) {
		remaining := int(leaf.NotAfter.Sub(now).Hours() / 24)
		return fmt.Errorf("headscale tls: cert expires within %d days (expiry: %s)", remaining, leaf.NotAfter.Format(time.RFC3339))
	}

	// Check SAN matches server URL hostname.
	if hs.ServerURL != "" {
		fqdn := extractHostname(hs.ServerURL)
		if fqdn != "" {
			if err := leaf.VerifyHostname(fqdn); err != nil {
				return fmt.Errorf("headscale tls: SAN mismatch for %q: %w", fqdn, err)
			}
		}
	}

	// Check key file permissions — group/world readable is a security failure.
	fi, err := os.Stat(keyPath) //nolint:gosec // G304: keyPath is a headscale key path resolved internally, not user input
	if err != nil {
		return fmt.Errorf("headscale tls: stat key file %s: %w", keyPath, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("headscale tls: key file %s is group/world readable (perm %04o)", keyPath, fi.Mode().Perm())
	}

	return nil
}

// ── HeadscaleDoctorChecks ─────────────────────────────────────────────────────

// HeadscaleDoctorChecks returns []modules.Finding for all nine hs-* doctor checks.
//
// The function signature accepts a doRequestFunc rather than a *headscaleAdapter to
// avoid coupling to the concrete adapter type — tests pass a mock, production code
// passes adapter.doRequest.
//
// Check ordering (per plan spec):
//  1. hs-lock — always appended first, unconditional SeverityWarning (no network needed)
//  2. Config-file checks (no network, no running server): hs-bind, hs-oidc-filter,
//     hs-derp-failclosed, hs-db-perms
//  3. Filesystem checks: hs-tls (calls ValidateHeadscaleTLS), hs-proc-user (shell.Runner)
//  4. REST checks (require running server): hs-api-auth, hs-key-expiry
func HeadscaleDoctorChecks(
	ctx context.Context,
	cfg *config.Config,
	runner shell.Runner,
	doReq doRequestFunc,
) ([]DoctorFinding, error) {
	var findings []DoctorFinding

	// ── 1. hs-lock: always first, unconditional, permanent WARN ───────────────
	// EXACT ROADMAP TEXT — must not be changed (plan must_haves, hs-lock invariant).
	findings = append(findings, DoctorFinding{
		Module:   "headscale",
		Check:    "hs-lock",
		Severity: DoctorWarning,
		Message:  "WARN: server-trust model only — Tailnet Lock (TKA) is not available on Headscale",
	})

	// ── 2. Config-file checks ─────────────────────────────────────────────────
	configPath := cfg.Server.Headscale.ConfigPath

	hsCfg, cfgParseErr := parseHsConfigYAML(configPath)
	if cfgParseErr != nil {
		slog.WarnContext(ctx, "headscale doctor: could not parse config.yaml", "err", cfgParseErr)
		// Emit WARN for all config-dependent checks and continue.
		for _, check := range []string{"hs-bind", "hs-oidc-filter", "hs-derp-failclosed"} {
			findings = append(findings, DoctorFinding{
				Module:   "headscale",
				Check:    check,
				Severity: DoctorWarning,
				Message:  fmt.Sprintf("hs-%s: could not complete check: %v", strings.TrimPrefix(check, "hs-"), cfgParseErr),
			})
		}
	} else {
		findings = append(findings, checkHsBind(hsCfg))
		findings = append(findings, checkHsOidcFilter(hsCfg))
		findings = append(findings, checkHsDerpFailclosed(hsCfg))
	}

	// hs-db-perms: os.Stat on the DB file.
	findings = append(findings, checkHsDbPerms(cfg.Server.Headscale.DBPath))

	// ── 3. Filesystem / process checks ───────────────────────────────────────

	// hs-tls: calls ValidateHeadscaleTLS and wraps the error as a Finding.
	findings = append(findings, checkHsTLS(ctx, cfg))

	// hs-proc-user: platform-conditional (systemctl on Linux, launchctl+ps on macOS).
	findings = append(findings, checkHsProcUser(ctx, runner))

	// ── 4. REST checks ────────────────────────────────────────────────────────

	// hs-api-auth: GET /api/v1/apikey
	findings = append(findings, checkHsAPIAuth(ctx, doReq))

	// hs-key-expiry: GET /api/v1/preauthkey
	findings = append(findings, checkHsKeyExpiry(ctx, doReq))

	return findings, nil
}

// ── Config-file checks ─────────────────────────────────────────────────────────

// hsConfigYAML is the loosely-typed struct for parsing Headscale config.yaml.
// Only keys needed by doctor checks are modelled; all others are preserved via
// the lenient (KnownFields false) decoder.
type hsConfigYAML struct {
	MetricsListenAddr string `yaml:"metrics_listen_addr"`
	GRPCAllowInsecure bool   `yaml:"grpc_allow_insecure"`
	ListenAddr        string `yaml:"listen_addr"`
	DERP              struct {
		Server struct {
			Enabled       bool `yaml:"enabled"`
			VerifyClients bool `yaml:"verify_clients"`
		} `yaml:"server"`
	} `yaml:"derp"`
	OIDC struct {
		Issuer           string   `yaml:"issuer"`
		AllowedDomains   []string `yaml:"allowed_domains"`
		AllowedUsers     []string `yaml:"allowed_users"`
		AllowedGroups    []string `yaml:"allowed_groups"`
		EmailVerifiedReq bool     `yaml:"email_verified_required"`
	} `yaml:"oidc"`
	Policy struct {
		Mode string `yaml:"mode"`
	} `yaml:"policy"`
}

// parseHsConfigYAML decodes a Headscale config.yaml with a lenient decoder.
func parseHsConfigYAML(path string) (*hsConfigYAML, error) {
	if path == "" {
		return nil, fmt.Errorf("headscale config path is empty")
	}
	f, err := os.Open(path) //nolint:gosec // G304: path is a headscale config path resolved internally, not user input
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // errcheck: close error on read-only/append file handle is non-actionable; data durability handled by explicit Sync where required

	var cfg hsConfigYAML
	dec := yaml.NewDecoder(f)
	// Lenient: preserve user's unknown keys.
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &cfg, nil
}

// checkHsBind checks port binding assertions in Headscale config.yaml.
// FAIL: metrics_listen_addr contains 0.0.0.0 (metrics exposed publicly).
// FAIL: grpc_allow_insecure==true (unauthenticated gRPC).
// WARN: listen_addr port is not :443.
func checkHsBind(cfg *hsConfigYAML) DoctorFinding {
	const check = "hs-bind"
	const mod = "headscale"

	if strings.Contains(cfg.MetricsListenAddr, "0.0.0.0") {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  fmt.Sprintf("metrics_listen_addr=%q exposes metrics publicly — must be loopback-only (127.0.0.1:9090)", cfg.MetricsListenAddr),
		}
	}
	if cfg.GRPCAllowInsecure {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  "grpc_allow_insecure: true — unauthenticated gRPC must not be exposed",
		}
	}
	if cfg.ListenAddr != "" && !strings.HasSuffix(cfg.ListenAddr, ":443") {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  fmt.Sprintf("listen_addr=%q uses non-standard port (expected :443) — Tailscale clients may not connect", cfg.ListenAddr),
		}
	}
	return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK, Message: "bind configuration is correct"}
}

// checkHsOidcFilter checks for open OIDC registration (D-12).
// SKIP/PASS: oidc.issuer absent or empty.
// FAIL: oidc.issuer non-empty AND all of allowed_domains/users/groups empty.
// WARN: issuer set, filter present, but email_verified_required==false.
func checkHsOidcFilter(cfg *hsConfigYAML) DoctorFinding {
	const check = "hs-oidc-filter"
	const mod = "headscale"

	if cfg.OIDC.Issuer == "" {
		// No OIDC configured — PASS (D-12: SKIP when absent).
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: "OIDC not configured — no open-registration vector"}
	}

	// OIDC is configured — check filter lists.
	hasFilter := len(cfg.OIDC.AllowedDomains) > 0 ||
		len(cfg.OIDC.AllowedUsers) > 0 ||
		len(cfg.OIDC.AllowedGroups) > 0

	if !hasFilter {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message: fmt.Sprintf(
				"OIDC issuer %q configured with empty allowed_domains, allowed_users, and allowed_groups — any identity provider user can register",
				cfg.OIDC.Issuer,
			),
		}
	}
	if !cfg.OIDC.EmailVerifiedReq {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "OIDC issuer configured but email_verified_required: false — unverified emails can register",
		}
	}
	return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK, Message: "OIDC filter is correctly configured"}
}

// checkHsDerpFailclosed checks whether embedded DERP verifies clients.
// PASS: derp.server.enabled AND derp.server.verify_clients.
// WARN: derp.server.enabled==false (external DERP only).
// FAIL: enabled but verify_clients==false (open relay).
func checkHsDerpFailclosed(cfg *hsConfigYAML) DoctorFinding {
	const check = "hs-derp-failclosed"
	const mod = "headscale"

	srv := cfg.DERP.Server
	if !srv.Enabled {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "derp.server.enabled=false — using external DERP only; ensure derp.urls is non-empty",
		}
	}
	if !srv.VerifyClients {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  "derp.server.enabled=true but verify_clients=false — embedded DERP is an open relay; any internet client can use it",
		}
	}
	return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
		Message: "embedded DERP is enabled with verify_clients=true (fail-closed)"}
}

// checkHsDbPerms checks SQLite DB file permissions.
// PASS: mode 0o600 (owner read/write only).
// WARN: mode 0o640 (group-readable).
// FAIL: mode 0o644 or broader, or file not found.
func checkHsDbPerms(dbPath string) DoctorFinding {
	const check = "hs-db-perms"
	const mod = "headscale"

	if dbPath == "" {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "hs-db-perms: db_path not configured"}
	}
	fi, err := os.Stat(dbPath) //nolint:gosec // G304: dbPath is a headscale DB path resolved internally, not user input
	if err != nil {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  fmt.Sprintf("SQLite DB not found at %s: %v", dbPath, err),
		}
	}
	perm := fi.Mode().Perm()
	switch perm {
	case 0o600:
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: fmt.Sprintf("SQLite DB perm %04o is correct", perm)}
	case 0o640:
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  fmt.Sprintf("SQLite DB is group-readable (perm %04o) — recommend 0600", perm),
		}
	default:
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  fmt.Sprintf("SQLite DB perm %04o is too broad (world-readable or wider) — set to 0600", perm),
		}
	}
}

// ── Filesystem / process checks ───────────────────────────────────────────────

// checkHsTLS calls ValidateHeadscaleTLS and wraps the returned error as a Finding.
// - nil return → SeverityOK (PASS)
// - error containing "within" → SeverityWarning (cert close to expiry)
// - any other error → SeverityFatal (FAIL)
// ValidateHeadscaleTLS is the single source of truth; this wrapper is the ONLY
// place that converts the error to a Finding.
func checkHsTLS(ctx context.Context, cfg *config.Config) DoctorFinding {
	const check = "hs-tls"
	const mod = "headscale"

	err := ValidateHeadscaleTLS(ctx, cfg)
	if err == nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK, Message: "TLS certificate is valid"}
	}
	msg := err.Error()
	if strings.Contains(msg, "within") {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning, Message: msg}
	}
	return DoctorFinding{Module: mod, Check: check, Severity: DoctorFatal, Message: msg}
}

// checkHsProcUser checks that the Headscale process runs as a non-root dedicated
// service user. Platform-conditional: Linux uses systemctl, macOS uses launchctl+ps.
// All shell calls go through shell.Runner (CLAUDE.md hard rule — never os/exec directly).
func checkHsProcUser(ctx context.Context, runner shell.Runner) DoctorFinding {
	const check = "hs-proc-user"
	const mod = "headscale"

	if runtime.GOOS == "darwin" {
		return checkHsProcUserMac(ctx, runner, check, mod)
	}
	return checkHsProcUserLinux(ctx, runner, check, mod)
}

// checkHsProcUserLinux probes Headscale's running user via systemctl on Linux.
func checkHsProcUserLinux(ctx context.Context, runner shell.Runner, check, mod string) DoctorFinding {
	res, err := runner.Run(ctx, "systemctl", "show", "headscale", "--property=User")
	if err != nil || res.ExitCode != 0 {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "hs-proc-user: systemctl could not query headscale service — service may not be installed",
		}
	}
	out := strings.TrimSpace(res.Stdout)
	if !strings.HasPrefix(out, "User=") {
		// Service not found or unexpected output.
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  fmt.Sprintf("hs-proc-user: unexpected systemctl output %q — cannot confirm non-root user", out),
		}
	}
	// systemd reports an empty User= when no User= directive is set, which means
	// the service runs as root. Parse the value rather than substring-matching so
	// the empty/root/0 cases are treated as Fatal (security check must not invert).
	user := strings.TrimPrefix(out, "User=")
	switch user {
	case "", "root", "0":
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  "Headscale service runs as root — must run as a dedicated non-root user",
		}
	case "headscale":
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorOK,
			Message:  "Headscale service runs as expected user (headscale)",
		}
	default:
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  fmt.Sprintf("Headscale service runs as %q — cannot confirm intended non-root user", user),
		}
	}
}

// checkHsProcUserMac probes Headscale's running user via launchctl+ps on macOS.
func checkHsProcUserMac(ctx context.Context, runner shell.Runner, check, mod string) DoctorFinding {
	res, err := runner.Run(ctx, "launchctl", "list", "net.abysslink.headscale")
	if err != nil || res.ExitCode != 0 {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "hs-proc-user: launchctl: headscale service not loaded (net.abysslink.headscale)",
		}
	}

	// Parse PID from launchctl output: "<pid> <status> <label>"
	pid := parseLaunchctlPID(res.Stdout)
	if pid == "" || pid == "-" || pid == "0" {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "hs-proc-user: headscale service is loaded but not running on macOS",
		}
	}

	psRes, psErr := runner.Run(ctx, "ps", "-p", pid, "-o", "user=")
	if psErr != nil || psRes.ExitCode != 0 {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  fmt.Sprintf("hs-proc-user: ps -p %s failed — cannot confirm non-root user", pid),
		}
	}
	user := strings.TrimSpace(psRes.Stdout)
	if user == "_headscale" {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
			Message: "Headscale service runs as _headscale (macOS)"}
	}
	return DoctorFinding{
		Module:   mod,
		Check:    check,
		Severity: DoctorFatal,
		Message:  fmt.Sprintf("Headscale service runs as %q on macOS — expected _headscale", user),
	}
}

// parseLaunchctlPID parses the PID from `launchctl list <label>` output.
// The first field of the line (after the label header) is the PID.
// Output format: "<pid>\t<exitstatus>\t<label>"
func parseLaunchctlPID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] != "PID" {
			return fields[0]
		}
	}
	return ""
}

// ── REST checks ───────────────────────────────────────────────────────────────

// checkHsAPIAuth verifies that the API key can authenticate against /api/v1/apikey.
// PASS: HTTP 200.
// FAIL: HTTP 401/403 or network error.
// WARN: any key expires within 14 days.
func checkHsAPIAuth(ctx context.Context, doReq doRequestFunc) DoctorFinding {
	const check = "hs-api-auth"
	const mod = "headscale"

	if doReq == nil {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "hs-api-auth: skipped — no API client available",
		}
	}

	resp, err := doReq(ctx, http.MethodGet, "/api/v1/apikey", nil)
	if err != nil {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  "Headscale API unreachable: " + err.Error(),
		}
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup

	switch resp.StatusCode {
	case http.StatusOK:
		// Check key expiry on active keys (if 14-day warn applies).
		warn := checkAPIKeyExpiry(resp)
		if warn != "" {
			return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning, Message: warn}
		}
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK, Message: "API key is valid and authenticated"}
	case http.StatusUnauthorized, http.StatusForbidden:
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  fmt.Sprintf("API key invalid or missing (HTTP %d)", resp.StatusCode),
		}
	default:
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorFatal,
			Message:  fmt.Sprintf("Headscale API returned HTTP %d", resp.StatusCode),
		}
	}
}

// checkAPIKeyExpiry reads the /api/v1/apikey response body and returns a WARN
// message if any key expires within 14 days. Returns empty string on no issue.
func checkAPIKeyExpiry(resp *http.Response) string {
	const warnDays = 14
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	var result struct {
		APIKeys []struct {
			Expiration string `json:"expiration"`
		} `json:"apiKeys"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	threshold := time.Now().Add(time.Duration(warnDays) * 24 * time.Hour)
	for _, key := range result.APIKeys {
		if key.Expiration == "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, key.Expiration)
		if err != nil {
			continue
		}
		if exp.Before(threshold) {
			return fmt.Sprintf("API key expires within %d days (%s) — rotate soon", warnDays, exp.Format(time.RFC3339))
		}
	}
	return ""
}

// checkHsKeyExpiry checks all active pre-auth keys for zero or past expiry.
// FAIL: any active (used==false) key has expiration=="0001-01-01T00:00:00Z" or <=now.
// WARN: no active pre-auth keys exist.
// PASS: all active keys have valid future expiry.
func checkHsKeyExpiry(ctx context.Context, doReq doRequestFunc) DoctorFinding {
	const check = "hs-key-expiry"
	const mod = "headscale"

	if doReq == nil {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "hs-key-expiry: skipped — no API client available",
		}
	}

	resp, err := doReq(ctx, http.MethodGet, "/api/v1/preauthkey", nil)
	if err != nil {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  "hs-key-expiry: could not complete check: " + err.Error(),
		}
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		return DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: DoctorWarning,
			Message:  fmt.Sprintf("hs-key-expiry: could not complete check: HTTP %d", resp.StatusCode),
		}
	}

	return parsePreAuthKeyExpiry(resp)
}

// hsPreAuthKeyListResponse is the response from GET /api/v1/preauthkey.
type hsPreAuthKeyListResponse struct {
	PreAuthKeys []struct {
		Used       bool   `json:"used"`
		Expiration string `json:"expiration"`
	} `json:"preAuthKeys"`
}

// zeroExpiry is the sentinel value returned by Headscale when no expiry is set.
const zeroExpiry = "0001-01-01T00:00:00Z"

// parsePreAuthKeyExpiry reads the pre-auth key list response and returns a finding.
func parsePreAuthKeyExpiry(resp *http.Response) DoctorFinding {
	const check = "hs-key-expiry"
	const mod = "headscale"

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "hs-key-expiry: could not read response body: " + err.Error()}
	}

	var result hsPreAuthKeyListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "hs-key-expiry: could not parse response: " + err.Error()}
	}

	now := time.Now()
	activeCount := 0

	for _, key := range result.PreAuthKeys {
		if key.Used {
			continue // skip used keys
		}
		activeCount++

		// Zero expiry (issue #1579 — never-expiring key created without explicit expiry).
		if key.Expiration == zeroExpiry {
			return DoctorFinding{
				Module:   mod,
				Check:    check,
				Severity: DoctorFatal,
				Message:  "active pre-auth key has zero expiry (0001-01-01T00:00:00Z) — closes upstream issue #1579; rotate key with explicit expiry",
			}
		}

		exp, err := time.Parse(time.RFC3339, key.Expiration)
		if err != nil {
			continue
		}
		if exp.Before(now) || exp.Equal(now) {
			return DoctorFinding{
				Module:   mod,
				Check:    check,
				Severity: DoctorFatal,
				Message:  fmt.Sprintf("active pre-auth key expired at %s — revoke and rotate", exp.Format(time.RFC3339)),
			}
		}
	}

	if activeCount == 0 {
		return DoctorFinding{Module: mod, Check: check, Severity: DoctorWarning,
			Message: "no active (unused) pre-auth keys — nothing to assert on expiry"}
	}
	return DoctorFinding{Module: mod, Check: check, Severity: DoctorOK,
		Message: fmt.Sprintf("all %d active pre-auth key(s) have valid non-zero expiry", activeCount)}
}
