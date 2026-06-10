//go:build webui

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

package webui

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"tailscale.com/client/local"
)

// tailnetIPResolver yields this node's tailnet IP. It is a seam so the bind
// resolver is unit-testable without a live tailscaled. The production
// implementation (localTailnetResolver) derives the IP from the Tailscale
// localapi Status; tests inject a stub.
type tailnetIPResolver interface {
	IP(ctx context.Context) (string, error)
}

// localTailnetResolver resolves the tailnet IP from the Tailscale localapi by
// reading Status.Self.TailscaleIPs[0]. It mirrors internal/tailscale.LocalClient.IP
// without importing that package, keeping the webui server self-contained on the
// tailscale.com/client/local seam it already uses for GetCertificate.
type localTailnetResolver struct{ lc *local.Client }

func (r localTailnetResolver) IP(ctx context.Context) (string, error) {
	st, err := r.lc.Status(ctx)
	if err != nil {
		return "", err
	}
	if st == nil || st.Self == nil || len(st.Self.TailscaleIPs) == 0 {
		return "", nil
	}
	return st.Self.TailscaleIPs[0].String(), nil
}

// resolveWebUIAddr determines the host:port the listener binds, failing closed
// (ok == false) rather than ever binding a non-tailnet interface (WEB-02). It
// mirrors the metrics server's resolveMetricsAddr (OBS-03):
//
//   - The backend-reported tailnet IP is resolved first. An empty,
//     unparseable, or unspecified IP fails closed (never a wildcard bind).
//   - When webui.bind_addr is empty (the default), the resolved tailnet IP is
//     bound directly.
//   - When webui.bind_addr is set, its host MUST equal the tailnet IP; a
//     wildcard, loopback, public/LAN, or mismatched host fails closed. A
//     bind_addr that carries its own port keeps it; a bare host is joined with
//     the configured/default port.
//
// Host/port precedence is delegated to config.EffectiveWebUIHostPort, the SAME
// helper the doctor live probe uses (webuiProbeURL), so the listener and the
// probe can never disagree about the effective port (WR-03).
func resolveWebUIAddr(ctx context.Context, cfg *config.Config, resolver tailnetIPResolver) (string, bool) {
	host, port := config.EffectiveWebUIHostPort(cfg)

	tailnetIP, err := resolver.IP(ctx)
	if err != nil {
		slog.Error("webui: resolve tailnet IP; refusing wildcard bind, listener disabled (WEB-02)", "err", err)
		return "", false
	}
	if tailnetIP == "" {
		// Fail closed: an empty host would make tls.Listen bind 0.0.0.0/:: (WEB-02).
		slog.Error("webui: empty tailnet IP; refusing wildcard bind, listener disabled (WEB-02)")
		return "", false
	}
	parsedTailnet := net.ParseIP(tailnetIP)
	if parsedTailnet == nil || parsedTailnet.IsUnspecified() {
		slog.Error("webui: non-tailnet/unspecified IP; listener disabled (WEB-02)", "ip", tailnetIP)
		return "", false
	}

	if host != "" {
		bindIP := net.ParseIP(host)
		if bindIP == nil || !bindIP.Equal(parsedTailnet) {
			slog.Error("webui: configured bind_addr is not the tailnet IP; listener disabled (WEB-02)",
				"bind_addr", cfg.WebUI.BindAddr, "tailnet_ip", tailnetIP)
			return "", false
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), true
	}

	return net.JoinHostPort(tailnetIP, strconv.Itoa(port)), true
}

// securityHeadersMiddleware applies the five non-CSRF security response headers
// that safeweb's serveBrowser() provided (tailscale.com@v1.98.5/safeweb/http.go:377-384).
// CSP string: derived from DefaultCSP() + Set("default-src","'self'") — no change to content.
// HSTS is always set because the listener is TLS-only (SecureContext was always true).
// Note: the correct W3C/RFC header name is "Referrer-Policy" (two r's); "Referer-Policy"
// (one r) is silently ignored by all browsers (WR-01).
func securityHeadersMiddleware(next http.Handler) http.Handler {
	const csp = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; " +
		"base-uri 'self'; block-all-mixed-content"
	const hsts = "max-age=31536000"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Strict-Transport-Security", hsts)
		next.ServeHTTP(w, r)
	})
}

// buildWebHandler composes the gorilla-free security middleware chain:
// CrossOriginProtection (CSRF replacement) → securityHeaders → mux.
// Replaces newSafewebServer (DEP-03 / D-08). Infallible — no error return.
func buildWebHandler(mux *http.ServeMux) http.Handler {
	cop := http.NewCrossOriginProtection()
	return cop.Handler(securityHeadersMiddleware(mux))
}

// StartWebUIServer builds the TLS listener, composes the security middleware
// chain (whoIsMiddleware -> readOnlyMiddleware -> CrossOriginProtection + securityHeaders),
// and serves until ctx is cancelled. It is LIBRARY code: every log line uses log/slog — nothing in
// this file writes to stdout or stderr via the fmt print family (CLAUDE.md hard
// rule). The loud one-time security note lives in the daemon entrypoint (Plan
// 04), not here.
//
// TLS is provisioned by the Tailscale daemon via local.Client.GetCertificate
// (WEB-03); no plaintext listener is ever created. Routes are registered in
// Plan 03 — for now the mux returns 404 for every path.
//
// The serve goroutine begins with a deferred recover so a panic in any handler
// or in Serve cannot crash the daemon process (T-19-18 / WARNING 6).
// ring may be nil, in which case StartWebUIServer constructs its own empty ring
// (the notify-history view then stays empty). The daemon entrypoint passes the
// same ring it injected into the daemon Server via SetRing so deliveries
// recorded in handleNotify appear in the /notify view (WEB-07).
// serverOptions holds the optional live data sources the daemon entrypoint
// injects. Both default to nil; with nil providers the views render their empty
// states (the handler nil-guards remain authoritative defenses).
type serverOptions struct {
	status StatusFunc
	doctor DoctorFunc
}

// Option configures StartWebUIServer. The daemon entrypoint (//go:build webui)
// uses WithStatusProvider/WithDoctorProvider to inject the real status and
// doctor data sources without this package importing internal/cli (the
// adapters live in package main, keeping the webui→cli boundary intact).
type Option func(*serverOptions)

// WithStatusProvider injects the fleet-status data source.
func WithStatusProvider(fn StatusFunc) Option {
	return func(o *serverOptions) { o.status = fn }
}

// WithDoctorProvider injects the doctor findings data source.
func WithDoctorProvider(fn DoctorFunc) Option {
	return func(o *serverOptions) { o.doctor = fn }
}

func StartWebUIServer(ctx context.Context, cfg *config.Config, ring *NotifyRingBuffer, opts ...Option) error {
	var lc local.Client // zero value uses the platform-default tailscaled socket
	ln, err := bindWebUIListener(ctx, cfg, &lc, localTailnetResolver{lc: &lc})
	if err != nil {
		return err
	}
	return serveWebUI(ctx, cfg, &lc, ln, ring, opts...)
}

// bindWebUIListener validates the config, resolves the tailnet-only bind
// address, and creates the TLS listener. It is split from the serve loop so
// callers (module.Apply) can bind SYNCHRONOUSLY and surface port-in-use /
// TLS-listen failures as errors instead of losing them inside the serve
// goroutine (W9).
//
// WEB-02 floor: resolve the listener address to the tailnet IP and FAIL
// CLOSED if it cannot be confirmed. An empty bind_addr binds the resolved
// tailnet IP; an explicit bind_addr must equal it. Never a wildcard bind.
// This mirrors the metrics server's resolveMetricsAddr (OBS-03) — the config
// validator only rejects an *explicit* 0.0.0.0/::, so without this the
// default empty bind_addr would have bound :8443 on every interface.
func bindWebUIListener(ctx context.Context, cfg *config.Config, lc *local.Client, resolver tailnetIPResolver) (net.Listener, error) {
	if err := config.ValidateWebUI(cfg); err != nil {
		return nil, err
	}
	addr, ok := resolveWebUIAddr(ctx, cfg, resolver)
	if !ok {
		// resolveWebUIAddr already logged the fail-closed reason. Never fall back
		// to a wildcard bind (WEB-02).
		return nil, fmt.Errorf("webui: refusing to bind; tailnet IP could not be confirmed (WEB-02)")
	}

	tlsCfg := &tls.Config{
		GetCertificate: lc.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("webui: tls listen %s: %w", addr, err)
	}
	return ln, nil
}

// serveWebUI composes the middleware chain and serves on an already-bound
// listener until ctx is cancelled. It owns ln and closes it on every exit path.
func serveWebUI(ctx context.Context, cfg *config.Config, lc *local.Client, ln net.Listener, ring *NotifyRingBuffer, opts ...Option) error {
	if ring == nil {
		ring = NewNotifyRingBuffer()
	}

	var so serverOptions
	for _, opt := range opts {
		opt(&so)
	}
	addr := ln.Addr().String()

	// The mux carries the four read-only view routes plus the embedded static
	// assets, and is wrapped by CrossOriginProtection+securityHeaders (CSRF/CSP),
	// then the read-only gate, then the WhoIs gate as the OUTERMOST handler so
	// unauthenticated peers never reach routing. The status/doctor providers come from the daemon
	// entrypoint via WithStatusProvider/WithDoctorProvider (B3): it adapts
	// internal/cli's CollectFleetStatus/CollectDoctorFindings so the dashboard
	// renders REAL posture data. When a provider is nil (e.g. the module.go
	// self-start path, or tests) the views render their empty states rather than
	// panicking — the handler nil-guards remain the authoritative defense.
	auditLogPath, err := audit.DefaultLogPath()
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("webui: audit log path: %w", err)
	}
	deps := HandlerDeps{
		Ring:         ring,
		AuditLogPath: auditLogPath,
		RigHostname:  cfg.Tailnet.Hostname,
		AllowNotify:  cfg.WebUI.AllowNotify,
	}
	if so.status != nil {
		deps.Status = statusFuncAdapter{fn: so.status}
	}
	if so.doctor != nil {
		deps.Doctor = doctorFuncAdapter{fn: so.doctor}
	}
	handlers, err := NewHandlers(deps)
	if err != nil {
		_ = ln.Close()
		return err
	}
	mux := http.NewServeMux()
	handlers.Register(mux)
	webHandler := buildWebHandler(mux)
	readOnly := readOnlyMiddleware(&cfg.WebUI, webHandler)
	outer := whoIsMiddleware(&lc, readOnly)

	srv := &http.Server{
		Handler:           outer,
		ReadHeaderTimeout: 5 * time.Second,
	}

	slog.Info("webui: listening", "addr", addr, "tls", true, "auth", "tailscale-whois")

	serveErr := make(chan error, 1)
	go func() {
		// FIRST statement: recover so a handler/Serve panic cannot take down the
		// daemon (T-19-18). Recovery is logged via slog, never printed.
		defer func() {
			if r := recover(); r != nil {
				slog.Error("webui: recovered panic", "recovered", r)
			}
		}()
		serveErr <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("webui: shutdown", "err", err)
		}
		_ = ln.Close()
		return ctx.Err()
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("webui: serve: %w", err)
		}
		return nil
	}
}
