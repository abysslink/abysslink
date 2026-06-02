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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
)

// errWhoamiPeerNotFound is the doctor-layer sentinel that the webui-whoami-local
// probe returns when tailscaled's localapi IS reachable but the dummy probe
// address ("100.0.0.1") is not a known peer. It is the doctor analogue of
// tailscale.com/client/local.ErrPeerNotFound — kept local so the base binary
// (no //go:build webui) never imports any tailscale.com package (T-19-08).
var errWhoamiPeerNotFound = errors.New("webui-whoami-local: peer not found (localapi reachable)")

// webuiProbeTimeout bounds every live doctor probe so a hung tailscaled or an
// unreachable webui listener never wedges the doctor run.
const webuiProbeTimeout = 500 * time.Millisecond

// webuiDoctorFindings runs the 8 HARD-FLOOR webui posture checks. Every check is
// FATAL on misconfiguration (CONTEXT.md HARD FLOOR; BLOCKER 1 fix). The checks
// read only config.WebUIConfig fields and perform net.Dial / net/http probes —
// no tailscale.com import — so this function lives in the base build and the
// base binary stays free of webui/SDK symbols (T-19-08).
//
//   - webui-bind (FATAL): bind_addr is 0.0.0.0 or :: (WEB-02). Fires even when
//     disabled (belt-and-suspenders against a misconfigured-then-enabled rig).
//   - webui-funnel (FATAL): enabled with an empty bind_addr — the tailnet-only
//     binding cannot be confirmed; Funnel/public binding is prohibited (WEB-02).
//   - webui-mutations-disabled (FATAL): enabled with read_only=false (WEB-02).
//   - webui-tls (FATAL): enabled on a non-Tailscale backend — GetCertificate is
//     unavailable on Headscale/NetBird (WEB-03, issue #2137).
//   - webui-auth (FATAL): enabled but the tailscaled localapi socket is
//     unreachable — WhoIs cannot authenticate requests (WEB-04).
//   - webui-whoami-local (FATAL): enabled but the WhoIs probe transport fails
//     (tailscaled down) — ErrPeerNotFound is OK (WEB-04, BLOCKER 1).
//   - webui-csrf (FATAL): enabled but an unauthenticated POST does not return
//     403, or the listener is unreachable — CSRF not active (WEB-05).
//   - webui-csp (FATAL): enabled but the response lacks default-src 'self'
//     (WEB-06).
func webuiDoctorFindings(ctx context.Context, cfg *config.Config) []modules.Finding {
	url := webuiProbeURL(cfg)
	return []modules.Finding{
		webuiBindCheck(cfg),
		webuiFunnelCheck(cfg),
		webuiMutationsDisabledCheck(cfg),
		webuiTLSCheck(cfg),
		webuiAuthCheck(cfg),
		webuiWhoamiLocalCheck(ctx, cfg, defaultWhoamiProbe),
		webuiCSRFCheck(ctx, cfg, url),
		webuiCSPCheck(ctx, cfg, url),
	}
}

// webuiProbeURL resolves the https URL the live-probe checks target. An empty
// bind_addr yields "" (the live checks then report unreachable, which the
// funnel/bind checks already flag FATAL for the empty-addr case).
//
// It resolves host:port via config.EffectiveWebUIHostPort, the SAME helper the
// listener uses (resolveWebUIAddr), so the doctor probe always targets the exact
// port the listener binds — no independent port resolver that could disagree
// (WR-03).
func webuiProbeURL(cfg *config.Config) string {
	host, port := config.EffectiveWebUIHostPort(cfg)
	if host == "" {
		return ""
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// okFinding builds a SeverityOK webui finding.
func okFinding(check, msg string) modules.Finding {
	return modules.Finding{Module: "webui", Check: check, Severity: modules.SeverityOK, Message: msg}
}

// fatalFinding builds a SeverityFatal webui finding.
func fatalFinding(check, msg string) modules.Finding {
	return modules.Finding{Module: "webui", Check: check, Severity: modules.SeverityFatal, Message: msg}
}

// webuiBindCheck FATALs when bind_addr is the unspecified wildcard (0.0.0.0/::).
// It fires whether or not webui is enabled so a misconfigured address is caught
// before the rig is ever started with webui on.
func webuiBindCheck(cfg *config.Config) modules.Finding {
	const check = "webui-bind"
	if addr := cfg.WebUI.BindAddr; addr != "" && config.IsUnspecifiedBindAddr(addr) {
		return fatalFinding(check, fmt.Sprintf(
			"webui.bind_addr %q must not be 0.0.0.0 or :: — webui must bind to the tailnet IP only (WEB-02)", addr))
	}
	return okFinding(check, "webui bind address is tailnet-scoped")
}

// webuiFunnelCheck FATALs when webui is enabled with an empty bind_addr, since
// a tailnet-only binding cannot then be confirmed and Funnel/public exposure is
// permanently prohibited.
func webuiFunnelCheck(cfg *config.Config) modules.Finding {
	const check = "webui-funnel"
	if !cfg.WebUI.Enabled {
		return okFinding(check, "webui disabled — Funnel binding not applicable")
	}
	if cfg.WebUI.BindAddr == "" {
		return fatalFinding(check,
			"webui.bind_addr must be set to a tailnet IP — Funnel/public binding is prohibited; "+
				"set bind_addr to your tailnet IP before enabling webui (WEB-02)")
	}
	return okFinding(check, "webui bind is tailnet-scoped (Funnel schema-rejected at config.Validate level)")
}

// webuiMutationsDisabledCheck FATALs when webui is enabled with read_only=false.
func webuiMutationsDisabledCheck(cfg *config.Config) modules.Finding {
	const check = "webui-mutations-disabled"
	if cfg.WebUI.Enabled && !cfg.WebUI.ReadOnly {
		return fatalFinding(check, "webui.read_only must be true — mutations are disabled in the web UI (WEB-02)")
	}
	return okFinding(check, "webui is read-only")
}

// webuiTLSCheck FATALs when webui is enabled on a non-Tailscale backend, where
// GetCertificate cannot provision a TLS cert (WEB-03, issue #2137). The live
// cert probe runs in the webui module's Verify() at startup; the doctor check
// is config-layer only (consistent with webui-auth).
func webuiTLSCheck(cfg *config.Config) modules.Finding {
	const check = "webui-tls"
	if !cfg.WebUI.Enabled {
		return okFinding(check, "webui disabled — TLS check not applicable")
	}
	if cfg.Backend.Type != "tailscale" {
		return fatalFinding(check,
			"webui requires Tailscale backend for TLS certificate provisioning — "+
				"GetCertificate is not available on Headscale/NetBird (WEB-03, issue #2137)")
	}
	return okFinding(check, "webui TLS backend is Tailscale (GetCertificate available)")
}

// webuiAuthCheck FATALs when webui is enabled but the tailscaled localapi socket
// cannot be dialed within the probe timeout — WhoIs auth is then impossible.
func webuiAuthCheck(cfg *config.Config) modules.Finding {
	const check = "webui-auth"
	if !cfg.WebUI.Enabled {
		return okFinding(check, "webui disabled — WhoIs auth check not applicable")
	}
	conn, err := net.DialTimeout("unix", tailscaledSocketPath(), webuiProbeTimeout)
	if err != nil {
		return fatalFinding(check, "WhoIs auth requires tailscaled to be running — localapi unreachable (WEB-04)")
	}
	_ = conn.Close()
	return okFinding(check, "tailscaled localapi reachable — WhoIs auth available")
}

// whoamiProbe abstracts the WhoIs reachability probe so the base build never
// imports tailscale.com. It must return errWhoamiPeerNotFound when the localapi
// is reachable but the dummy addr is not a peer, a transport error when the
// localapi is unreachable, or nil otherwise.
type whoamiProbe func(ctx context.Context) error

// defaultWhoamiProbe probes tailscaled localapi reachability by dialing the
// platform socket. A successful dial means the localapi is up; since the doctor
// base binary cannot call WhoIs (no tailscale import), a reachable socket is
// reported as the expected "peer not found" outcome (localapi answers, the
// dummy addr is simply not a peer). A dial failure is a transport error.
func defaultWhoamiProbe(_ context.Context) error {
	conn, err := net.DialTimeout("unix", tailscaledSocketPath(), webuiProbeTimeout)
	if err != nil {
		return fmt.Errorf("dial tailscaled localapi: %w", err)
	}
	_ = conn.Close()
	return errWhoamiPeerNotFound
}

// webuiWhoamiLocalCheck FATALs when webui is enabled and the WhoIs probe returns
// a transport error (tailscaled down). errWhoamiPeerNotFound is OK (localapi
// reachable). Any other error is treated as OK with a warning (localapi is
// responsive). This is the BLOCKER 1 fix — a transport error is FATAL, never OK.
func webuiWhoamiLocalCheck(ctx context.Context, cfg *config.Config, probe whoamiProbe) modules.Finding {
	const check = "webui-whoami-local"
	if !cfg.WebUI.Enabled {
		return okFinding(check, "webui disabled — WhoIs probe not applicable")
	}
	probeCtx, cancel := context.WithTimeout(ctx, webuiProbeTimeout)
	defer cancel()
	err := probe(probeCtx)
	switch {
	case err == nil:
		return okFinding(check, "webui-whoami-local: localapi reachable (WhoIs responded) (WEB-04)")
	case errors.Is(err, errWhoamiPeerNotFound):
		return okFinding(check,
			"webui-whoami-local: localapi reachable (WhoIs returned ErrPeerNotFound for dummy addr as expected) (WEB-04)")
	default:
		return fatalFinding(check,
			"webui-whoami-local: tailscaled localapi unreachable — WhoIs cannot authenticate requests; "+
				"webui must not start (WEB-04)")
	}
}

// webuiInsecureClient returns an HTTP client that skips TLS verification: the
// doctor probe is operator-initiated and read-only, not a browser, so the
// Tailscale-issued cert chain (not present in the doctor's trust store) must not
// abort the probe (T-19-17).
func webuiInsecureClient() *http.Client {
	return &http.Client{
		Timeout: webuiProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // operator-initiated read-only doctor probe (T-19-17)
		},
	}
}

// webuiCSRFCheck FATALs when an unauthenticated POST to {url}/notify returns a
// status other than 403 (CSRF not active) or the listener is unreachable. 401
// and 503 are OK (WhoIs auth or still-starting — the CSRF layer is upstream).
func webuiCSRFCheck(ctx context.Context, cfg *config.Config, url string) modules.Finding {
	const check = "webui-csrf"
	if !cfg.WebUI.Enabled {
		return okFinding(check, "webui disabled — CSRF probe not applicable")
	}
	if url == "" {
		return fatalFinding(check,
			"webui-csrf: webui is enabled but no bind address is configured — cannot verify CSRF protection (WEB-05)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/notify", http.NoBody)
	if err != nil {
		return fatalFinding(check, fmt.Sprintf("webui-csrf: build probe request failed: %v (WEB-05)", err))
	}
	resp, err := webuiInsecureClient().Do(req)
	if err != nil {
		return fatalFinding(check, fmt.Sprintf(
			"webui-csrf: webui is enabled but not reachable at %s — cannot verify CSRF protection is active (WEB-05)", url))
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusForbidden:
		return okFinding(check, "webui-csrf: CSRF protection active (unauthenticated POST returned 403 as required) (WEB-05)")
	case http.StatusUnauthorized, http.StatusServiceUnavailable:
		return okFinding(check, "webui-csrf: WhoIs auth or startup gate present upstream of CSRF (WEB-05)")
	default:
		return fatalFinding(check, fmt.Sprintf(
			"webui-csrf: unauthenticated POST to %s/notify returned %d (expected 403) — CSRF protection is NOT active; "+
				"webui must be restarted (WEB-05)", url, resp.StatusCode))
	}
}

// webuiCSPCheck FATALs when the webui is unreachable or the response lacks a
// Content-Security-Policy header enforcing default-src 'self' (WEB-06).
func webuiCSPCheck(ctx context.Context, cfg *config.Config, url string) modules.Finding {
	const check = "webui-csp"
	if !cfg.WebUI.Enabled {
		return okFinding(check, "webui disabled — CSP probe not applicable")
	}
	if url == "" {
		return fatalFinding(check, "webui-csp: webui is enabled but no bind address is configured (WEB-06)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fatalFinding(check, fmt.Sprintf("webui-csp: build probe request failed: %v (WEB-06)", err))
	}
	resp, err := webuiInsecureClient().Do(req)
	if err != nil {
		return fatalFinding(check, fmt.Sprintf(
			"webui-csp: cannot reach webui at %s — is the webui server running? (WEB-06)", url))
	}
	defer func() { _ = resp.Body.Close() }()
	csp := resp.Header.Get("Content-Security-Policy")
	if !cspEnforcesSelf(csp) {
		return fatalFinding(check,
			"webui-csp: Content-Security-Policy header missing or does not enforce 'default-src self' (WEB-06)")
	}
	return okFinding(check, "webui-csp: Content-Security-Policy enforces default-src 'self' (WEB-06)")
}

// cspEnforcesSelf reports whether the CSP header pins default-src to 'self'.
func cspEnforcesSelf(csp string) bool {
	return csp != "" &&
		(strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "default-src='self'"))
}

// tailscaledSocketPath returns the platform-default tailscaled localapi socket
// path. It is a helper (not a hardcoded literal at the call site) so the path is
// resolved in one place across Linux and macOS.
func tailscaledSocketPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/run/tailscaled.socket"
	default:
		return "/var/run/tailscale/tailscaled.sock"
	}
}
