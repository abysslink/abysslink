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
	"tailscale.com/safeweb"
)

// defaultWebUIPort is the TLS listen port used when webui.port is unset. It
// mirrors config.Defaults() (8443) so the listener and the schema agree.
const defaultWebUIPort = 8443

// webuiAddr resolves the host:port the listener binds. An empty bind_addr is
// resolved to the tailnet IP at the daemon seam (Plan 04); here it falls back
// to the loopback-free unspecified-host form only for address construction —
// the listener itself is only ever created after ValidateWebUI and the TLS
// probe pass, so a wildcard bind is rejected upstream (WEB-02).
func webuiAddr(cfg *config.Config) string {
	port := cfg.WebUI.Port
	if port <= 0 {
		port = defaultWebUIPort
	}
	host := cfg.WebUI.BindAddr
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// buildCSP returns the Content-Security-Policy for all browser responses. It
// starts from safeweb's hardened default and pins default-src to 'self' only —
// no unsafe-inline and no external origins/CDN (WEB-06). All styling lives in
// the embedded same-origin stylesheet.
func buildCSP() safeweb.CSP {
	csp := safeweb.DefaultCSP()
	csp.Set("default-src", "'self'")
	return csp
}

// newSafewebServer constructs the safeweb.Server that wraps mux with CSRF
// protection and the restrictive CSP. Routes MUST be registered on BrowserMux
// (not via Config.HTTPServer.Handler, which safeweb ignores — Pitfall 2). The
// CSRF secret is auto-generated (crypto/rand) when omitted, which is the
// correct ephemeral-per-restart posture for the daemon (WEB-05).
func newSafewebServer(mux *http.ServeMux) (*safeweb.Server, error) {
	sw, err := safeweb.NewServer(safeweb.Config{
		SecureContext: true, // Secure CSRF cookie + HSTS
		BrowserMux:    mux,  // all routes get CSRF + CSP
		CSP:           buildCSP(),
	})
	if err != nil {
		return nil, fmt.Errorf("webui: safeweb: %w", err)
	}
	return sw, nil
}

// StartWebUIServer builds the TLS listener, composes the security middleware
// chain (whoIsMiddleware -> readOnlyMiddleware -> safeweb), and serves until ctx
// is cancelled. It is LIBRARY code: every log line uses log/slog — nothing in
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
func StartWebUIServer(ctx context.Context, cfg *config.Config, ring *NotifyRingBuffer) error {
	if err := config.ValidateWebUI(cfg); err != nil {
		return err
	}
	if ring == nil {
		ring = NewNotifyRingBuffer()
	}

	addr := webuiAddr(cfg)

	var lc local.Client // zero value uses the platform-default tailscaled socket
	tlsCfg := &tls.Config{
		GetCertificate: lc.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("webui: tls listen %s: %w", addr, err)
	}

	// The mux carries the four read-only view routes plus the embedded static
	// assets, and is wrapped by safeweb (CSRF + CSP), then the read-only gate,
	// then the WhoIs gate as the OUTERMOST handler so unauthenticated peers
	// never reach routing. The status/doctor providers are nil here; the daemon
	// entrypoint (Plan 04) injects the live data sources via a future seam. With
	// nil providers the views render their empty states rather than panicking.
	auditLogPath, err := audit.DefaultLogPath()
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("webui: audit log path: %w", err)
	}
	handlers, err := NewHandlers(HandlerDeps{
		Ring:         ring,
		AuditLogPath: auditLogPath,
		RigHostname:  cfg.Tailnet.Hostname,
	})
	if err != nil {
		_ = ln.Close()
		return err
	}
	mux := http.NewServeMux()
	handlers.Register(mux)
	sw, err := newSafewebServer(mux)
	if err != nil {
		_ = ln.Close()
		return err
	}
	readOnly := readOnlyMiddleware(&cfg.WebUI, sw)
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
