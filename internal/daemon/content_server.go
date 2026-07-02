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

package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/shell"
)

// Content-listener constants (BACK-06/BACK-07).
const (
	// maxContentBodyBytes caps the optional v2 envelope content field; bodies
	// beyond it are rejected with 413 (the wake's fallback title still covers
	// the event — the sender should trim, not the daemon).
	maxContentBodyBytes = 64 * 1024
	// maxAckBody caps the POST /ack request body — it carries one msg_id.
	maxAckBody = 4 * 1024
	// staleDeviceWindow is the DEVC-04 quiet-device threshold surfaced in
	// GET /status (7 days).
	staleDeviceWindow = 7 * 24 * time.Hour
	// contentShutdownTimeout bounds the content listener's graceful drain.
	contentShutdownTimeout = 3 * time.Second
)

// msgIDRe is the ULID shape POST /ack accepts: 26 Crockford-base32 chars with
// the 48-bit-timestamp first-char bound (0-7). notifyv2 validates msg_id with
// ulid.ParseStrict but does not export a helper, so the shape is pinned
// locally (matching ParseStrict's charset and overflow rule).
var msgIDRe = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// DeviceStore is the daemon-side view of the enrolled-device registry
// (internal/device.Store satisfies it; tests inject a fake). VerifyBearer is
// constant-time inside the implementation and fails closed.
type DeviceStore interface {
	VerifyBearer(presented string) (*device.Record, bool)
	TouchLastSeen(ctx context.Context, id string, when time.Time) error
	List() []device.Record
	Stale(window time.Duration) []device.Record
}

// AuditAppender appends one hash-only entry to the audit chain. *audit.Audit
// (and via it the chain-aware signed path) satisfies it — the same
// entry-append API the reverse/restore path uses. content is HASHED by the
// implementation (SHA-256 into the entry), never stored.
type AuditAppender interface {
	Append(op, target string, content []byte, dryRun bool) error
}

// Compile-time guard: the chain-aware audit writer must keep satisfying the
// receipt-append contract, so interface drift fails here.
var _ AuditAppender = (*audit.Audit)(nil)

// ContentTLSProvider yields the TLS config for the content listener. The
// production provider (cmd/abysslinkd) wraps the Tailscale local client's
// GetCertificate — the same WEB-03 path the webui listener uses; it lives in
// the entrypoint so this package stays free of Tailscale SDK imports. A nil
// provider or a provider error means TLS material is unavailable and the
// listener stays disabled (fail closed — never a plaintext listener).
type ContentTLSProvider func(ctx context.Context) (*tls.Config, error)

// tailnetIPResolver yields this node's tailnet IP. Seam so the bind resolver
// is unit-testable without a live backend (mirrors the webui listener seam).
type tailnetIPResolver interface {
	IP(ctx context.Context) (string, error)
}

// tailnetHostResolver yields this node's MagicDNS hostname (e.g.
// myrig.tail1234.ts.net). Seam so the advertise-host resolution is
// unit-testable without a live backend (mirrors tailnetIPResolver). The
// listener BINDS the tailnet IP regardless; this only affects the host placed
// in the minted FetchRef URL so a TLS-verifying phone fetch verifies against
// the Tailscale-issued *.ts.net cert SAN (Finding 2).
type tailnetHostResolver interface {
	Hostname(ctx context.Context) (string, error)
}

// backendIPResolver is the production resolver: backend.New → Client.IP, the
// single source of truth for "what is this node's tailnet address" (the same
// floor resolveMetricsAddr enforces, OBS-03). It never propagates a panic —
// the backend localapi probe can panic when tailscaled is absent.
type backendIPResolver struct {
	cfg    *config.Config
	runner shell.Runner
}

func (r backendIPResolver) IP(ctx context.Context) (ip string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			ip, err = "", fmt.Errorf("daemon: tailnet IP probe panicked: %v", rec)
		}
	}()
	b, berr := backend.New(r.cfg, r.runner)
	if berr != nil || b == nil {
		return "", fmt.Errorf("daemon: backend unavailable: %w", berr)
	}
	return b.IP(ctx)
}

// backendHostResolver is the production MagicDNS-hostname resolver: backend.New
// → Client.Hostname, the same source the IP resolver uses. It never propagates
// a panic — the backend localapi probe can panic when tailscaled is absent. A
// missing hostname is not fatal here: the content listener still binds the IP
// and only the advertised FetchRef URL host degrades (Finding 2).
type backendHostResolver struct {
	cfg    *config.Config
	runner shell.Runner
}

func (r backendHostResolver) Hostname(ctx context.Context) (host string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			host, err = "", fmt.Errorf("daemon: tailnet hostname probe panicked: %v", rec)
		}
	}()
	b, berr := backend.New(r.cfg, r.runner)
	if berr != nil || b == nil {
		return "", fmt.Errorf("daemon: backend unavailable: %w", berr)
	}
	// PREFER the full MagicDNS name (Status.Self.DNSName, e.g.
	// "rig.tail1234.ts.net.") over the short HostName ("rig"): the advertised
	// FetchRef host must match the Tailscale-issued cert SAN, which is the FQDN.
	// Client.Hostname returns only the short HostName, which fails the .ts.net
	// suffix check in resolveContentAdvertiseHost and silently degrades the pull
	// URL to the bind IP (a TLS-SAN mismatch on the phone). Fall back to the
	// short hostname only when DNSName is unavailable.
	if st, serr := b.Status(ctx); serr == nil {
		if dns := selfDNSName(st); dns != "" {
			return dns, nil
		}
	}
	return b.Hostname(ctx)
}

// selfDNSName returns this node's MagicDNS FQDN from a backend status, or "" if
// unavailable. The returned name may carry a trailing dot (resolveContentAdvertiseHost
// trims it before the *.ts.net suffix check).
func selfDNSName(st *backend.Status) string {
	if st != nil && st.Self != nil {
		return st.Self.DNSName
	}
	return ""
}

// SetDeviceStore injects the enrolled-device registry consumed by the content
// listener's bearer gate and GET /status's devices block. Called by the
// composition root before Run; nil-safe: without it the content listener
// stays disabled (fail closed) and /status reports an empty devices list.
func (s *Server) SetDeviceStore(d DeviceStore) { s.devices = d }

// SetAuditAppender injects the audit chain writer used for BACK-07 ack
// receipts. Called by the composition root before Run; nil-safe: without it
// POST /ack fails with 500 (a receipt-less ack would be a fake receipt).
func (s *Server) SetAuditAppender(a AuditAppender) { s.auditApp = a }

// SetContentTLS injects the TLS provider for the content listener. Called by
// the composition root before Run; nil-safe: without TLS material the
// listener stays disabled (fail closed — never plaintext, never 0.0.0.0).
func (s *Server) SetContentTLS(p ContentTLSProvider) { s.contentTLS = p }

// disableContent records the content listener as disabled with one honest
// warning (the daemon and unix socket keep running — fail closed means no
// listener, never a wider bind).
func (s *Server) disableContent(reason string, kv ...any) {
	s.contentMu.Lock()
	s.contentLive = false
	s.contentStatus = "disabled: " + reason
	s.contentMu.Unlock()
	slog.Warn("daemon: content listener disabled — "+reason, kv...)
}

// contentStoreStatus returns the /status content_store string
// ("listening on <addr>" or "disabled: <reason>").
func (s *Server) contentStoreStatus() string {
	s.contentMu.Lock()
	defer s.contentMu.Unlock()
	return s.contentStatus
}

// resolveContentAddr determines the host the content listener binds, failing
// closed (ok == false) rather than ever binding a non-tailnet interface. It
// mirrors resolveMetricsAddr (OBS-03): the backend-reported tailnet IP is the
// single source of truth; an explicit content_store.bind_addr must equal it.
// Any failure — resolver error, empty/unspecified IP, mismatched bind_addr —
// fails closed with no listener (never a wildcard bind).
func (s *Server) resolveContentAddr(ctx context.Context, resolver tailnetIPResolver) (string, bool) {
	tailnetIP, err := resolver.IP(ctx)
	if err != nil {
		slog.Warn("daemon: content listener: resolve tailnet IP failed", "err", err)
		return "", false
	}
	if tailnetIP == "" {
		// Fail closed: an empty host would make tls.Listen bind 0.0.0.0/::.
		slog.Warn("daemon: content listener: empty tailnet IP; refusing wildcard bind")
		return "", false
	}
	parsed := net.ParseIP(tailnetIP)
	if parsed == nil || parsed.IsUnspecified() {
		slog.Warn("daemon: content listener: non-tailnet/unspecified IP; refusing bind", "ip", tailnetIP)
		return "", false
	}
	if bindAddr := strings.TrimSpace(s.cfg.ContentStore.BindAddr); bindAddr != "" {
		bindIP := net.ParseIP(bindAddr)
		if bindIP == nil || !bindIP.Equal(parsed) {
			slog.Warn("daemon: content listener: configured bind_addr is not the tailnet IP; refusing bind (BACK-06)",
				"bind_addr", bindAddr, "tailnet_ip", tailnetIP)
			return "", false
		}
		return bindAddr, true
	}
	return tailnetIP, true
}

// resolveContentAdvertiseHost determines the host placed in the minted FetchRef
// URL (Finding 2). It PREFERS the node's MagicDNS hostname when it is a
// non-empty *.ts.net name, so a TLS-verifying phone fetch verifies against the
// Tailscale-issued cert (which carries only the *.ts.net SAN, no tailnet-IP
// SAN). When the hostname is unavailable or not a *.ts.net name it falls back
// to the bind IP — DEGRADED, never fail-closed: the listener still binds the IP
// and serves, only the advertised URL host differs (a phone may then need to
// trust the IP, and the BACK-08 fallback title still covers a failed fetch).
// Either result passes notifyv2.Validate's url_tailnet rule (a *.ts.net name,
// a CGNAT IPv4, or a Tailscale ULA IPv6 are all accepted).
// hostResolverOrDefault returns the injected MagicDNS-hostname seam, or the
// production backendHostResolver when none was injected (same backend source
// as the IP resolver).
func (s *Server) hostResolverOrDefault() tailnetHostResolver {
	if s.contentHostResolver != nil {
		return s.contentHostResolver
	}
	return backendHostResolver{cfg: s.cfg, runner: s.runner}
}

func (s *Server) resolveContentAdvertiseHost(ctx context.Context, bindIP string, resolver tailnetHostResolver) string {
	if resolver == nil {
		return bindIP
	}
	host, err := resolver.Hostname(ctx)
	if err != nil {
		slog.Warn("daemon: content listener: MagicDNS hostname unavailable; advertising bind IP in fetch URL (degraded — a phone may need to trust the IP)",
			"err", err, "bind_ip", bindIP)
		return bindIP
	}
	host = strings.TrimSpace(host)
	// Tailscale's GetCertificate issues a leaf for the FQDN; tolerate a
	// trailing dot on the reported name so the advertised host matches the SAN.
	host = strings.TrimSuffix(host, ".")
	if host == "" || !strings.HasSuffix(host, ".ts.net") {
		slog.Warn("daemon: content listener: hostname is not a *.ts.net MagicDNS name; advertising bind IP in fetch URL (degraded)",
			"hostname", host, "bind_ip", bindIP)
		return bindIP
	}
	return host
}

// probeContentCert eagerly fetches the TLS leaf ONCE so a tailnet with HTTPS
// Certificates disabled (or otherwise unable to mint a cert) fails closed with
// an honest reason rather than binding a listener whose every handshake later
// dies silently. It returns true (proceed) when the probe succeeds OR when it
// is deliberately skipped; it calls disableContent and returns false only on a
// genuine probe failure.
//
// Skip conditions (NOT failures):
//   - tlsCfg.GetCertificate is nil: the cert is served from a static
//     tlsCfg.Certificates slice (the test seam, and any non-localapi provider),
//     so there is nothing to probe — the listener will use it directly.
//   - advertiseHost is a bare IP, not a *.ts.net hostname: the leaf is issued
//     for the MagicDNS FQDN, so a SAN-correct probe needs the hostname. When we
//     are advertising a bare IP (the degraded resolveContentAdvertiseHost
//     fallback) a phone TLS verify would already fail on its own; probing with
//     an IP ServerName would false-disable a listener that may still work for a
//     client that trusts the IP, so we skip and let the existing degraded path
//     stand.
func (s *Server) probeContentCert(tlsCfg *tls.Config, advertiseHost string) bool {
	if tlsCfg.GetCertificate == nil {
		return true
	}
	// Only probe when the advertise host is a MagicDNS hostname (the SAN the
	// Tailscale leaf is issued for). A bare IP means we are already in the
	// degraded advertise path; do not false-disable on it.
	if net.ParseIP(advertiseHost) != nil || !strings.Contains(advertiseHost, ".") {
		return true
	}
	if _, certErr := tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: advertiseHost}); certErr != nil {
		s.disableContent("tailnet HTTPS certs unavailable — enable HTTPS Certificates in the Tailscale admin DNS page (https://login.tailscale.com/admin/dns)", "err", certErr)
		return false
	}
	return true
}

// resolveContentPreconditions runs every fail-closed gate that must pass before
// the content listener can bind: config enabled + valid, a device store, a TLS
// provider, a confirmed tailnet bind IP, a resolvable advertise host, real TLS
// material, and an eager cert probe. It returns (host, advertiseHost, tlsCfg,
// true) when the listener may proceed; on any failure it calls disableContent
// with the specific reason and returns ok=false. Extracted from
// startContentServer to keep that function under the gocyclo ceiling.
func (s *Server) resolveContentPreconditions(ctx context.Context) (host, advertiseHost string, tlsCfg *tls.Config, ok bool) {
	if s.cfg == nil || !s.cfg.ContentStore.Enabled {
		s.disableContent("content_store.enabled is false")
		return "", "", nil, false
	}
	// Re-enforce the config floor at the listener seam (the CR-02 pattern):
	// a programmatically-built config bypassing Load must still fail closed.
	if err := config.ValidateContentStore(s.cfg); err != nil {
		s.disableContent("invalid content_store config", "err", err)
		return "", "", nil, false
	}
	if s.devices == nil {
		s.disableContent("no device store (bearer auth unavailable)")
		return "", "", nil, false
	}
	if s.contentTLS == nil {
		s.disableContent("TLS material unavailable (no certificate provider)")
		return "", "", nil, false
	}
	resolver := s.contentResolver
	if resolver == nil {
		resolver = backendIPResolver{cfg: s.cfg, runner: s.runner}
	}
	host, addrOK := s.resolveContentAddr(ctx, resolver)
	if !addrOK {
		// resolveContentAddr already logged the specific reason.
		s.disableContent("bind address could not be confirmed as the tailnet IP (BACK-06)")
		return "", "", nil, false
	}
	// Resolve the advertise host (Finding 2): prefer the *.ts.net MagicDNS name
	// so a TLS-verifying phone fetch verifies against the cert SAN. This NEVER
	// fails the listener — a missing/non-ts.net hostname falls back to the bind
	// IP (degraded). The listener still binds `host` (the tailnet IP).
	advertiseHost = s.resolveContentAdvertiseHost(ctx, host, s.hostResolverOrDefault())
	cfg, err := s.contentTLS(ctx)
	if err != nil || cfg == nil {
		s.disableContent("TLS material unavailable", "err", err)
		return "", "", nil, false
	}
	// Eager cert probe (Finding: silent TLS-handshake failure). The content
	// listener serves the leaf via GetCertificate (the Tailscale localapi cert
	// path) LAZILY — so with HTTPS Certificates DISABLED on the tailnet, the
	// listener binds and /status reads "listening", yet every phone TLS
	// handshake dies ("server stopped responding"). Probe the cert ONCE here so
	// that failure surfaces as an honest disabled-with-reason instead of a
	// cryptic runtime handshake error. If the probe fails we fail closed — a
	// listener that can never complete a handshake is worse than no listener.
	if !s.probeContentCert(cfg, advertiseHost) {
		return "", "", nil, false
	}
	return host, advertiseHost, cfg, true
}

// startContentServer resolves the tailnet-only bind address, builds the TLS
// listener, and serves the content endpoints until ctx is cancelled
// (BACK-06). Every precondition failure disables the listener with one honest
// warning while the daemon and its unix socket keep running; "fail closed"
// here always means NO listener — never a wider bind, never plaintext.
func (s *Server) startContentServer(ctx context.Context) {
	host, advertiseHost, tlsCfg, ok := s.resolveContentPreconditions(ctx)
	if !ok {
		// resolveContentPreconditions already disabled with the specific reason.
		return
	}

	port := s.cfg.ContentStore.EffectivePort()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		s.disableContent("tls listen failed", "addr", addr, "err", err)
		return
	}
	// The configured port may be 0 (tests); read the real bound port back.
	if tcpAddr, isTCP := ln.Addr().(*net.TCPAddr); isTCP {
		port = tcpAddr.Port
	}

	srv := &http.Server{
		Handler:           s.buildContentMux(),
		ReadHeaderTimeout: readHeaderTO,
		IdleTimeout:       idleTO,
	}

	s.contentMu.Lock()
	s.contentLive = true
	s.contentHost = host
	s.contentAdvertiseHost = advertiseHost
	s.contentPort = port
	s.contentStatus = "listening on " + net.JoinHostPort(host, strconv.Itoa(port))
	s.contentMu.Unlock()
	slog.Info("daemon: content listener up", "addr", ln.Addr().String())

	go s.content.runPruner(ctx)

	// Drain on shutdown: registered with contentWG so Run's shutdown path
	// waits for the drain to finish (clean shutdown drains, NET-14 voice).
	s.contentWG.Add(1)
	go func() {
		defer s.contentWG.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), contentShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		s.contentMu.Lock()
		s.contentLive = false
		s.contentStatus = "disabled: daemon shutting down"
		s.contentMu.Unlock()
	}()

	go func() {
		// FIRST statement: recover so a handler/Serve panic cannot take down
		// the daemon (the webui T-19-18 pattern).
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("daemon: content listener recovered panic", "recovered", rec)
			}
		}()
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.disableContent("serve failed", "err", serveErr)
		}
	}()
}

// buildContentMux returns the content listener's OWN mux — deliberately
// separate from the unix-socket mux, so /notify, /status, and /sessions are
// never exposed on a network listener (WR-04).
func (s *Server) buildContentMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /content/{token}", s.handleContent)
	mux.HandleFunc("GET /enroll/{token}", s.handleBootstrap) // BACK-09: bearer-LESS first-contact pull
	mux.HandleFunc("POST /ack", s.handleAck)
	// Phase 30: bearer-LESS approve/deny capability-URL handlers (APPR-04).
	// These are on the content mux (network-exposed HTTPS) — the phone reaches
	// them by tapping the capability URL the daemon sends in the notification.
	mux.HandleFunc("GET /approve/{token}", s.handleApprove)
	mux.HandleFunc("GET /deny/{token}", s.handleDeny)
	return mux
}

// handleApprove serves GET /approve/{token} (APPR-04): bearer-LESS, constant-
// work, single-use. Token entropy is the only credential (256-bit, base64url);
// HMAC verification is defense-in-depth (D-16). A valid lookup CAS-resolves the
// pending request to Approved, writes an audit receipt (APPR-03), and returns 200.
// All miss paths (unknown/expired/wrong-kind token, HMAC mismatch, unknown request)
// return a uniform empty-body 404 — no oracle distinguishes miss types (T-30-07/08).
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	// Cap body (defense in depth — GET carries no meaningful body).
	r.Body = http.MaxBytesReader(w, r.Body, maxAckBody)
	token := r.PathValue("token")

	// lookupKind: kind checked BEFORE the single-use consume (BACK-09 invariant).
	// A deny token presented here is a cross-kind miss that burns nothing (T-30-08).
	requestID, found := s.content.lookupKind(token, kindApprove, true)
	if !found {
		s.writeApproveMiss(w, r)
		return
	}
	if s.approveRegistry == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Lookup stored HMAC sig + closureHash for D-16 verification.
	hmacSig, closureHash, _, lookOK := s.approveRegistry.Lookup(requestID)
	if !lookOK {
		// Request not found in registry (expired/pruned) — uniform miss, no oracle.
		s.writeApproveMiss(w, r)
		return
	}

	// HMAC verify (D-16, T-30-11): mismatch → uniform miss, same as any miss.
	if len(s.approveHMACKey) > 0 {
		if !approve.VerifyApproveURL(s.approveHMACKey, requestID, "approve", closureHash, hmacSig) {
			slog.Warn("daemon: approve HMAC mismatch — returning uniform 404",
				"request_id", reqIDPrefix(requestID))
			s.writeApproveMiss(w, r)
			return
		}
	}

	// CAS resolve: first-answer-wins (APPR-02). A false return means another
	// goroutine already won; log and return 200 (late tap is not an error).
	won := s.approveRegistry.Resolve(requestID, approve.StateApproved)
	if !won {
		slog.Debug("daemon: late approve resolution ignored — already resolved",
			"request_id", reqIDPrefix(requestID))
	}

	// IN-03: gate audit + counter mutations on won so a lost-CAS late tap is
	// a pure no-op (no double audit receipt, no double counter).
	if won {
		// Audit receipt (APPR-03): content is hashed by Append; raw values never reach the log.
		if s.auditApp != nil {
			receipt := []byte(requestID + "\n" + "approve" + "\n" + hex.EncodeToString(closureHash[:]))
			if err := s.auditApp.Append("approve-decision", "request:"+reqIDPrefix(requestID), receipt, false); err != nil {
				// Non-fatal: log at Warn; the approval is already registered (CAS won above).
				slog.Warn("daemon: approve audit append failed", "err", err)
			}
		}
		// Counters: increment approved, decrement pending.
		s.approveApproved.Add(1)
		s.approvePending.Add(-1)
	}

	// HTML confirmation for the phone (ntfy view tap opens Safari); JSON otherwise.
	// Render the REAL final decision: a late Approve tap that LOST the CAS (already
	// denied by the TTY arm or a headless timeout-deny) must NOT falsely render
	// "Approved — will continue" on a security surface (finding [23]).
	approved, known := s.finalApproveOutcome(requestID, won, true)
	if !known {
		s.writeApproveMiss(w, r)
		return
	}
	s.writeApproveResult(w, r, approved, reqIDPrefix(requestID))
}

// handleDeny serves GET /deny/{token} (APPR-04): identical structure to
// handleApprove but resolves the pending request to Denied. The audit receipt
// uses action="deny" and the denied counter increments.
func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAckBody)
	token := r.PathValue("token")

	requestID, found := s.content.lookupKind(token, kindDeny, true)
	if !found {
		s.writeApproveMiss(w, r)
		return
	}
	if s.approveRegistry == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// CR-03: look up the deny HMAC sig via LookupDeny, which retrieves the
	// denyHmacSig stored on the main entry (signed over the real closure hash).
	// The previous side-channel (requestID+":deny" with a zero closure hash)
	// caused every phone-deny to fail HMAC verification (fail-open deny defect).
	hmacSig, closureHash, _, lookOK := s.approveRegistry.LookupDeny(requestID)
	if !lookOK {
		s.writeApproveMiss(w, r)
		return
	}

	// HMAC verify (D-16, T-30-11).
	if len(s.approveHMACKey) > 0 {
		if !approve.VerifyApproveURL(s.approveHMACKey, requestID, "deny", closureHash, hmacSig) {
			slog.Warn("daemon: deny HMAC mismatch — returning uniform 404",
				"request_id", reqIDPrefix(requestID))
			s.writeApproveMiss(w, r)
			return
		}
	}

	won := s.approveRegistry.Resolve(requestID, approve.StateDenied)
	if !won {
		slog.Debug("daemon: late deny resolution ignored — already resolved",
			"request_id", reqIDPrefix(requestID))
	}

	// IN-03: gate audit + counter mutations on won so a lost-CAS late tap is
	// a pure no-op (no double audit receipt, no double counter decrement).
	if won {
		if s.auditApp != nil {
			receipt := []byte(requestID + "\n" + "deny" + "\n" + hex.EncodeToString(closureHash[:]))
			if err := s.auditApp.Append("approve-decision", "request:"+reqIDPrefix(requestID), receipt, false); err != nil {
				slog.Warn("daemon: deny audit append failed", "err", err)
			}
		}
		s.approveDenied.Add(1)
		s.approvePending.Add(-1)
	}

	// HTML confirmation for the phone (ntfy view tap opens Safari); JSON otherwise.
	// Render the REAL final decision: a late Deny tap that LOST the CAS (already
	// approved) must NOT falsely render "Denied — blocked" while the approved
	// command actually runs (finding [23]).
	approved, known := s.finalApproveOutcome(requestID, won, false)
	if !known {
		s.writeApproveMiss(w, r)
		return
	}
	s.writeApproveResult(w, r, approved, reqIDPrefix(requestID))
}

// wantsHTML reports whether the caller is a browser (the ntfy "view" tap opens
// Safari, which sends Accept: text/html). Programmatic callers and tests send
// */* or no Accept and get JSON.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// approvePageShell renders the self-contained HTML confirmation page shown after
// a phone taps an approve/deny capability URL. Inline CSS, no external assets, no
// JS, mobile-first, respects light/dark. Every interpolated value is a
// compile-time constant or the safe 8-char request prefix (hex/ULID), so no
// untrusted input reaches the markup.
func approvePageShell(iconClass, icon, heading, sub, meta string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">` +
		`<title>` + heading + ` · abysslink</title><style>` +
		`:root{color-scheme:light dark}*{box-sizing:border-box}` +
		`body{margin:0;min-height:100svh;display:grid;place-items:center;padding:24px;` +
		`font:17px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;` +
		`background:#0b0f14;color:#e6edf3}` +
		`@media(prefers-color-scheme:light){body{background:#f6f8fa;color:#1f2328}}` +
		`.card{width:100%;max-width:360px;text-align:center;padding:40px 28px;border-radius:22px;` +
		`background:color-mix(in srgb,currentColor 5%,transparent);` +
		`border:1px solid color-mix(in srgb,currentColor 14%,transparent)}` +
		`.icon{width:80px;height:80px;border-radius:50%;margin:0 auto 22px;display:grid;` +
		`place-items:center;font-size:38px;line-height:1;color:#fff}` +
		`.ok{background:#1f883d}.no{background:#cf222e}.muted{background:#6e7781}` +
		`h1{margin:0 0 8px;font-size:25px;font-weight:650;letter-spacing:-.01em}` +
		`p{margin:0;font-size:15px;opacity:.7}` +
		`.meta{margin-top:24px;font-size:12px;opacity:.5}` +
		`</style></head><body><div class="card">` +
		`<div class="icon ` + iconClass + `">` + icon + `</div>` +
		`<h1>` + heading + `</h1><p>` + sub + `</p>` +
		`<div class="meta">` + meta + `</div></div></body></html>`
}

// approveResultPage is the confirmation page for a resolved request.
func approveResultPage(approved bool, reqPrefix string) string {
	if approved {
		return approvePageShell("ok", "✓", "Approved", "The tool call will continue.", "abysslink · request "+reqPrefix)
	}
	return approvePageShell("no", "✕", "Denied", "The tool call was blocked.", "abysslink · request "+reqPrefix)
}

// approveMissPage is the uniform page for every miss reason — byte-identical so
// it reveals nothing about why the link failed (no-oracle, T-30-07/08).
func approveMissPage() string {
	return approvePageShell("muted", "⌛", "Link no longer valid",
		"This approval link was already used, has expired, or isn't recognized.", "abysslink")
}

// writeApproveMiss writes the uniform miss response: a no-oracle HTML page for a
// browser, or an empty-body 404 for programmatic callers. Identical for every
// miss reason so it never distinguishes miss types.
func (s *Server) writeApproveMiss(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if wantsHTML(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, approveMissPage())
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

// finalApproveOutcome resolves the REAL decision to render on the phone
// confirmation page after a capability-URL tap (finding [23]). On a won CAS the
// outcome is the tapped action. On a lost CAS the request was already resolved —
// possibly the OPPOSITE way (a TTY/phone deny, or a headless timeout-deny) — so
// it reads the registry's actual resolved state rather than asserting the tapped
// action succeeded, which would be a false safety signal on a security surface.
// known=false means the request is no longer in the registry (already pruned);
// the caller then shows the neutral miss page rather than fabricate a decision.
func (s *Server) finalApproveOutcome(requestID string, won, tappedApproved bool) (approved, known bool) {
	if won {
		return tappedApproved, true
	}
	st, resolved := s.approveRegistry.StateOf(requestID)
	if !resolved {
		return false, false
	}
	return st == approve.StateApproved, true
}

// writeApproveResult writes the 200 result: an HTML confirmation page for a
// browser (the ntfy view tap), or compact JSON for programmatic callers.
// reqPrefix is the safe 8-char request prefix — never the full ID/token.
func (s *Server) writeApproveResult(w http.ResponseWriter, r *http.Request, approved bool, reqPrefix string) {
	w.Header().Set("Cache-Control", "no-store")
	if wantsHTML(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, approveResultPage(approved, reqPrefix))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"approved": approved, "request_id": reqPrefix}); err != nil {
		slog.Debug("daemon: approve result encode failed", "err", err)
	}
}

// verifyRequestBearer extracts the Authorization: Bearer credential and
// verifies it against the device store (constant-time inside VerifyBearer).
// Missing header, malformed header, unknown bearer, and revoked device all
// return (nil, false) indistinguishably.
func (s *Server) verifyRequestBearer(r *http.Request) (*device.Record, bool) {
	if s.devices == nil {
		return nil, false
	}
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || presented == "" {
		return nil, false
	}
	return s.devices.VerifyBearer(presented)
}

// handleContent serves GET /content/{token} (BACK-06). Auth failures
// (missing/unknown/revoked bearer) and token misses (unknown or expired) are
// a UNIFORM 404 with an empty body — no oracle distinguishes "bad bearer"
// from "bad token". Success returns the body as text/plain with
// Cache-Control: no-store and touches the device's last-seen.
//
// Finding 3 (constant work): the token lookup runs on BOTH the authed and the
// auth-failed path so a bad bearer cannot be distinguished from a good bearer
// by skipping the store's lock+prune work (a — very low, 256-bit-bearer —
// timing oracle for bearer validity). The lookup CONSUMES the token only when
// auth succeeded: an auth-failed request never deletes a valid token
// (preserving single-use for the legitimate fetch) and never touches last-seen
// (an unauthenticated request must not move a device's last-seen — a different
// leak). The 404 response is byte-identical (empty body, no headers) on every
// failure branch.
func (s *Server) handleContent(w http.ResponseWriter, r *http.Request) {
	// A GET carries no meaningful body; cap it anyway (defense in depth).
	r.Body = http.MaxBytesReader(w, r.Body, maxAckBody)
	rec, authed := s.verifyRequestBearer(r)
	// Always run the lookup (constant work), but consume the token only when
	// the bearer is valid — so an auth-failed request cannot burn a live token.
	body, found := s.content.lookupContent(r.PathValue("token"), authed)
	if !authed || !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// #nosec G705 -- not XSS: Content-Type is text/plain (set above), never
	// text/html, so the browser does not parse the body as markup; the body is a
	// server-minted notification body, not attacker-controlled HTML. (gosec's
	// taint analysis flags it only because the BACK-09 /enroll/stage input now
	// shares the content store; the served content-type is the real guard.)
	if _, err := w.Write([]byte(body)); err != nil { //nosec G705
		slog.Debug("daemon: content write failed", "err", err)
	}
	if err := s.devices.TouchLastSeen(r.Context(), rec.ID, time.Now()); err != nil {
		slog.Debug("daemon: touch last-seen failed", "err", err)
	}
}

// handleBootstrap serves GET /enroll/{token} (BACK-09): the first-contact,
// bearer-LESS credential-bundle pull. There is NO device bearer at first
// contact — the high-entropy single-use token IS the only credential — so this
// handler deliberately does NOT call verifyRequestBearer. The bootstrap KIND is
// checked before the single-use consume (lookupKind), so a content token (or
// any non-bootstrap token) is a uniform 404 that burns nothing — a bearer-less
// /enroll request can never read a bearer-gated message body. Success returns
// the staged bundle JSON as application/json with Cache-Control: no-store.
//
// Constant work + uniform 404: a bad token, an expired token, and a wrong-class
// token are byte-identical empty-body 404s; lookupKind always runs the same
// lock+prune work. Unlike handleContent there is no TouchLastSeen — the device
// is not yet enrolled from the daemon's view, so there is no record to touch.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	// A GET carries no meaningful body; cap it anyway (defense in depth).
	r.Body = http.MaxBytesReader(w, r.Body, maxAckBody)
	// Preview-safe (BACK-09): a link-preview/crawler that fetches the pasted URL
	// (iMessage/Slack/WhatsApp/…) must NEVER reach the single-use consume below —
	// otherwise it would BURN the token before the real user opens it and LEAK
	// the credential bundle to the crawler's servers. Detect well-known preview
	// User-Agents and serve a generic non-secret placeholder instead: no burn (we
	// return before lookupKind), no leak (no bundle), no oracle (the placeholder
	// is identical whether or not the token exists). A bot spoofing a browser UA
	// falls through to the normal path — same risk as any first-fetcher today.
	if isPreviewBot(r.UserAgent()) {
		writeEnrollPreviewPlaceholder(w)
		return
	}
	body, found := s.content.lookupKind(r.PathValue("token"), kindBootstrap, true)
	if !found {
		// A scanner/browser that opened a dead/expired/used link gets a clear
		// "link expired" page instead of a blank white 404; an explicit JSON
		// caller keeps the empty-body 404 (uniform, no-oracle — the page is
		// generic). The constant-work lookup already ran above.
		if wantsJSON(r) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeEnrollNotFoundHTML(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// HTML is the DEFAULT (the link is a QR for a human to scan): the formatted
	// credential page with per-field Copy/Download. Only an explicit JSON caller
	// (?format=json or Accept: application/json) gets raw JSON. Both are this
	// single (already-consumed) response — no second fetch. On any HTML render
	// error, fall back to JSON so the credentials are never lost.
	if !wantsJSON(r) {
		err := writeEnrollHTML(w, body)
		if err == nil {
			return
		}
		// HTML render failed — fall through to JSON so credentials are never lost.
		slog.Debug("daemon: bootstrap html render failed; serving json", "err", err)
	}
	w.Header().Set("Content-Type", "application/json")
	// #nosec G705 -- not XSS: Content-Type is application/json (data, not markup);
	// the human-facing page goes through html/template (writeEnrollHTML). The body
	// is the server-staged bundle, served verbatim as JSON.
	if _, err := w.Write([]byte(body)); err != nil { //nosec G705
		// Opaque error only — never the body or token (CLAUDE.md no-secrets-in-log).
		slog.Debug("daemon: bootstrap write failed", "err", err)
	}
}

// ackRequest is the POST /ack JSON body.
type ackRequest struct {
	MsgID string `json:"msg_id"`
}

// handleAck serves POST /ack (BACK-07): a phone-side true delivery receipt.
// The bearer gate is identical to GET /content (uniform 404 on any auth
// failure). On success it appends a HASH-ONLY receipt to the audit chain —
// the entry records sha256(msg_id + "\n" + device.ID) and nothing else; no
// message content (the daemon never has it at ack time) and no raw msg_id
// ever reaches the log. Then ack_received increments, the device's last-seen
// is touched, and 204 is returned.
//
// A missed ack triggers NOTHING — by design there is no re-wake logic
// anywhere in the daemon (BACK-07: "a missed ack never triggers an automatic
// re-wake"). The receipt exists purely so `abysslink status` can report
// wake-sent vs ack-received honestly.
func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.verifyRequestBearer(r)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAckBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req ackRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid ack payload", http.StatusBadRequest)
		return
	}
	if !msgIDRe.MatchString(req.MsgID) {
		http.Error(w, "msg_id is not a valid ULID", http.StatusBadRequest)
		return
	}

	if s.auditApp == nil {
		// A receipt-less ack would be a fake receipt; fail honestly.
		http.Error(w, "receipt store unavailable", http.StatusInternalServerError)
		return
	}
	// Hash-only receipt: Append hashes the content into the entry (SHA-256),
	// so the logged hash IS sha256(msg_id + "\n" + device.ID) — the raw
	// msg_id and device binding never appear in the log.
	if err := s.auditApp.Append("ack-receipt", "device:"+rec.ID, []byte(req.MsgID+"\n"+rec.ID), false); err != nil {
		slog.Warn("daemon: ack receipt append failed", "err", err)
		http.Error(w, "receipt write failed", http.StatusInternalServerError)
		return
	}
	s.ackReceived.Add(1)
	if err := s.devices.TouchLastSeen(r.Context(), rec.ID, time.Now()); err != nil {
		slog.Debug("daemon: touch last-seen failed", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// AckReceiptHash returns the hex receipt digest recorded in the audit chain
// for (msgID, deviceID) — exported so `abysslink devices`/status tooling and
// tests can recompute the BACK-07 receipt without duplicating the format.
func AckReceiptHash(msgID, deviceID string) string {
	sum := sha256.Sum256([]byte(msgID + "\n" + deviceID))
	return fmt.Sprintf("%x", sum)
}

// mintFetchRef mints a content token for body and composes the FetchRef the
// dispatched message carries (BACK-06). Returns (nil, false) when the content
// listener is not live — the caller then drops the content and dispatches the
// wake unchanged, relying on the BACK-08 fallback title.
func (s *Server) mintFetchRef(body string) (urlTailnet string, ttlSeconds int, ok bool) {
	s.contentMu.Lock()
	live, advertiseHost, port := s.contentLive, s.contentAdvertiseHost, s.contentPort
	s.contentMu.Unlock()
	if !live {
		return "", 0, false
	}
	// Advertise the MagicDNS *.ts.net host (Finding 2) so a TLS-verifying phone
	// fetch verifies against the Tailscale-issued cert SAN; the listener still
	// binds the tailnet IP. JoinHostPort keeps an IPv6-literal fallback host
	// bracketed. A *.ts.net name, a CGNAT IPv4, or a Tailscale ULA IPv6 all pass
	// notifyv2.Validate's url_tailnet rule.
	ttl := s.cfg.ContentStore.EffectiveTTL()
	token, _ := s.content.mintContent(body, ttl)
	u := "https://" + net.JoinHostPort(advertiseHost, strconv.Itoa(port)) + "/content/" + token
	return u, int(ttl / time.Second), true
}
