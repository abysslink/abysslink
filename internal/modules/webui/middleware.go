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
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/abysslink/abysslink/internal/config"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
)

// ctxKeyLoginName is the unexported context key under which the authenticated
// tailnet login name is stored after a successful WhoIs lookup. Using an
// unexported zero-size type prevents collisions with any other context value.
type ctxKeyLoginName struct{}

// whoIser is the WhoIs seam the auth middleware depends on. *local.Client
// satisfies it; tests inject a mock so the gate can be exercised without a live
// tailscaled. Keeping the surface to a single method makes the trust boundary
// explicit.
type whoIser interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// compile-time assertion that the real Tailscale client satisfies the seam.
var _ whoIser = (*local.Client)(nil)

// whoIsMiddleware authenticates every request against the Tailscale WhoIs
// identity gate. There is NO trusted-local bypass: a request whose RemoteAddr
// is unparseable, is a loopback address (127.0.0.1 / ::1), resolves to no
// tailnet peer (ErrPeerNotFound), errors at the daemon, or carries a nil
// UserProfile is answered with 403 (WEB-04 HARD FLOOR). The loopback gate runs
// FIRST, before any WhoIs call, so a loopback connection never even reaches the
// daemon (T-19-04).
//
// On success the authenticated LoginName is injected into the request context
// under ctxKeyLoginName for display-only use by templates (no other PII).
func whoIsMiddleware(w whoIser, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			denyAccess(rw)
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsLoopback() {
			// WEB-04: loopback and unparseable hosts are rejected before any
			// WhoIs call — never a trusted-local bypass.
			denyAccess(rw)
			return
		}

		info, err := w.WhoIs(r.Context(), r.RemoteAddr)
		switch {
		case errors.Is(err, local.ErrPeerNotFound):
			denyAccess(rw)
			return
		case err != nil:
			// tailscaled unreachable or other transport error — fail closed.
			slog.Warn("webui: whois failed", "err", err)
			denyAccess(rw)
			return
		case info == nil || info.UserProfile == nil:
			// Defensive: a peer with no profile cannot be authenticated
			// (Pitfall 3 — mocks and edge cases may return a nil profile).
			denyAccess(rw)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyLoginName{}, info.UserProfile.LoginName)
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

// readOnlyMiddleware is the HTTP-layer half of the two-layer read-only gate
// (WEB-02). Safe methods (GET, HEAD, OPTIONS) always pass. Every mutating
// method is rejected with 403 EXCEPT the single explicitly-unlocked
// allow_notify path: a POST to "/notify" passes only when cfg.AllowNotify is
// true. Cross-origin enforcement for that path is handled by
// CrossOriginProtection (buildWebHandler) below this middleware, not here.
//
// OPTIONS is allowed through as a "safe" method for completeness, but no route
// matches it and CrossOriginProtection configures no CORS, so a preflight falls
// through to a 404 — CORS preflight is intentionally unsupported (same-origin only) (IN-02).
func readOnlyMiddleware(cfg *config.WebUIConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(rw, r)
			return
		}
		if cfg.AllowNotify && r.Method == http.MethodPost && r.URL.Path == "/notify" {
			next.ServeHTTP(rw, r)
			return
		}
		http.Error(rw, "mutations are disabled (WEB-02)", http.StatusForbidden)
	})
}

// loginNameFromContext returns the authenticated tailnet login name injected by
// whoIsMiddleware, or "" if the request was not authenticated through it. It is
// used by templates to render the header login (display-only, WEB-07).
func loginNameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyLoginName{}).(string); ok {
		return v
	}
	return ""
}

// denyAccess writes the canonical 403 response. The message is generic so it
// never reveals why authentication failed (V7 error-handling posture).
func denyAccess(rw http.ResponseWriter) {
	http.Error(rw, "access denied", http.StatusForbidden)
}
