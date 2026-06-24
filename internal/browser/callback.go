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

package browser

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"time"
)

// CallbackOpts configures the RFC 8252 loopback OAuth callback server.
type CallbackOpts struct {
	// State is the cryptographically random OAuth state parameter embedded in
	// the authorization URL. ListenCallback rejects any callback where the
	// received state does not match using crypto/subtle.ConstantTimeCompare.
	State string

	// Nonce is the OIDC nonce (optional). Empty string skips nonce validation.
	Nonce string

	// CodeVerifier is the PKCE code verifier (RFC 7636). If set,
	// CodeChallenge(CodeVerifier) was sent in the authorization URL; any
	// callback carrying a mismatched code_challenge is rejected.
	CodeVerifier string

	// Timeout is how long to wait before returning a timeout error. Zero means
	// use the ctx deadline exclusively.
	Timeout time.Duration

	// OnReady is called immediately after the listener is bound and before the
	// handler wait. It receives the redirectURI so callers can open the browser
	// or trigger test callbacks. May be nil.
	OnReady func(redirectURI string)
}

// callbackResult carries the outcome of a single /callback handler invocation.
type callbackResult struct {
	code string
	err  error
}

// ListenCallback starts an RFC 8252 loopback OAuth callback server on
// 127.0.0.1 with an OS-assigned ephemeral port (D-05 IMMUTABLE). It blocks
// until it receives one callback or ctx is cancelled/times out.
//
// On success, returns (authCode, redirectURI, nil). On failure (state
// mismatch, PKCE failure, timeout, cancellation), returns ("", redirectURI,
// error).
//
// Security invariants:
//   - net.Listen is HARDCODED to "tcp", "127.0.0.1:0" — never configurable.
//   - State and nonce are validated with crypto/subtle.ConstantTimeCompare.
//   - http.Server.Shutdown is called on ALL exit paths (success + cancel) to
//     prevent goroutine leaks (T-35-OAuth-dos).
func ListenCallback(ctx context.Context, opts CallbackOpts) (code string, redirectURI string, err error) {
	// D-05 IMMUTABLE: bind to 127.0.0.1:0 exclusively — never 0.0.0.0 or a
	// fixed port. The OS assigns an ephemeral port at Listen time.
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:gosec // G102: loopback-only is the security requirement (D-05)
	if err != nil {
		return "", "", fmt.Errorf("browser callback: listen: %w", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // net.Listen("tcp",...) always returns *net.TCPAddr
	redirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	done := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", makeCallbackHandler(opts, done))

	srv := &http.Server{Handler: mux} //nolint:gosec // no TLS needed: loopback-only per RFC 8252 §8.3; no external exposure
	go func() {
		_ = srv.Serve(ln) //nolint:errcheck // ErrServerClosed is expected when Shutdown is called
	}()

	// Notify caller that the server is ready and provide the redirectURI.
	// This is called before blocking on the done channel so tests can trigger
	// the fake browser callback, and production callers can open the browser.
	if opts.OnReady != nil {
		opts.OnReady(redirectURI)
	}

	// Wait for a callback result or context cancellation.
	// Shutdown is called on BOTH paths to prevent goroutine leaks (T-35-OAuth-dos).
	return waitForCallback(ctx, srv, redirectURI, done)
}

// waitForCallback waits for a result from the done channel or ctx cancellation,
// then shuts down srv. Called only by ListenCallback.
func waitForCallback(ctx context.Context, srv *http.Server, redirectURI string, done <-chan callbackResult) (string, string, error) {
	var result callbackResult
	select {
	case result = <-done:
		// Received callback result — shut down the server cleanly.
		_ = srv.Shutdown(context.Background()) //nolint:errcheck // ErrServerClosed is not an error here
	case <-ctx.Done():
		// Context cancelled or timed out — shut down the server cleanly.
		_ = srv.Shutdown(context.Background()) //nolint:errcheck // ErrServerClosed is not an error here
		return "", redirectURI, ctx.Err()
	}

	if result.err != nil {
		return "", redirectURI, result.err
	}
	return result.code, redirectURI, nil
}

// makeCallbackHandler returns an http.HandlerFunc that validates the OAuth
// callback parameters (state, PKCE, nonce) and sends a callbackResult to done.
// Extracted from ListenCallback to keep gocyclo <= 15.
func makeCallbackHandler(opts CallbackOpts, done chan<- callbackResult) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		result := validateCallback(q, opts)
		if result.err != nil {
			writeErrorPage(w, result.err.Error())
		} else {
			writeSuccessPage(w)
		}
		select {
		case done <- result:
		default:
			// done is buffered(1); a second callback is silently dropped.
		}
	}
}

// validateCallback checks all OAuth callback parameters and returns a
// callbackResult. Returns err != nil if any validation fails.
func validateCallback(q interface{ Get(string) string }, opts CallbackOpts) callbackResult {
	// OAuth error from the authorization server.
	if oauthErr := q.Get("error"); oauthErr != "" {
		desc := q.Get("error_description")
		return callbackResult{err: fmt.Errorf("authorization error: %s: %s", oauthErr, desc)}
	}

	// Validate state with constant-time compare (T-35-OAuth-csrf).
	// NEVER use == for state comparison.
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(opts.State)) != 1 {
		return callbackResult{err: fmt.Errorf("browser callback: state mismatch (CSRF protection)")}
	}

	// Validate PKCE code_challenge if a verifier was configured (T-35-OAuth-pkce).
	if opts.CodeVerifier != "" {
		if cc := q.Get("code_challenge"); cc != "" {
			if subtle.ConstantTimeCompare([]byte(cc), []byte(CodeChallenge(opts.CodeVerifier))) != 1 {
				return callbackResult{err: fmt.Errorf("browser callback: PKCE code_challenge mismatch")}
			}
		}
	}

	// Validate OIDC nonce if provided.
	if opts.Nonce != "" {
		if subtle.ConstantTimeCompare([]byte(q.Get("nonce")), []byte(opts.Nonce)) != 1 {
			return callbackResult{err: fmt.Errorf("browser callback: nonce mismatch")}
		}
	}

	authCode := q.Get("code")
	if authCode == "" {
		return callbackResult{err: fmt.Errorf("browser callback: no code in callback")}
	}

	return callbackResult{code: authCode}
}

// writeSuccessPage writes a minimal HTML success response to the OAuth callback.
func writeSuccessPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>
<h1>Authorization received.</h1>
<p>You may close this tab and return to the terminal.</p>
</body></html>`))
}

// writeErrorPage writes a minimal HTML error response to the OAuth callback.
func writeErrorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>
<h1>Authorization failed.</h1>
<p>` + msg + `</p>
</body></html>`))
}
