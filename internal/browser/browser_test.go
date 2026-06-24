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

// Package browser_test contains stub tests that define the contract for
// internal/browser. All stubs are skipped until Wave 3 implements the package.
package browser_test

import (
	"context"
	"io"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
)

// recordingRunner implements shell.Runner and captures the name and args of the
// last Run call. It is used by BRWS-01 tests to assert that OpenURL routes
// through runner.Run("open", url) rather than calling os/exec directly.
type recordingRunner struct {
	lastName string
	lastArgs []string
}

// Compile-time check: recordingRunner must satisfy the shell.Runner interface.
// This keeps lint happy while tests are in stub/skip phase.
var _ shell.Runner = (*recordingRunner)(nil)

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (shell.Result, error) {
	r.lastName = name
	r.lastArgs = append([]string{}, args...)
	return shell.Result{ExitCode: 0}, nil
}

func (r *recordingRunner) RunWithStdin(_ context.Context, _ io.Reader, name string, args ...string) (shell.Result, error) {
	r.lastName = name
	r.lastArgs = append([]string{}, args...)
	return shell.Result{ExitCode: 0}, nil
}

func (r *recordingRunner) RunInteractive(_ context.Context, _ string, _ ...string) error {
	return nil
}

func (r *recordingRunner) RunWithEnv(_ context.Context, _ map[string]string, name string, args ...string) (shell.Result, error) {
	r.lastName = name
	r.lastArgs = append([]string{}, args...)
	return shell.Result{ExitCode: 0}, nil
}

func (r *recordingRunner) RunStream(_ context.Context, _ string, _ ...string) (*shell.Stream, error) {
	return nil, nil //nolint:nilnil // recordingRunner is a test stub; nil stream is intentional
}

// TestOpenURL_RoutesViaRunner asserts that browser.OpenURL routes the browser
// launch through shell.Runner.Run("open"/"xdg-open", url) and never calls
// os/exec directly (BRWS-01, D-06 IMMUTABLE).
func TestOpenURL_RoutesViaRunner(t *testing.T) {
	t.Skip("TODO: internal/browser not yet implemented — Wave 3")
}

// TestOpenURLHeadless_NeverSpawns asserts that on a non-interactive (headless)
// terminal, OpenURL emits the URL without spawning a browser process (D-07,
// D-08: never auto-open headless).
func TestOpenURLHeadless_NeverSpawns(t *testing.T) {
	t.Skip("TODO: internal/browser not yet implemented — Wave 3")
}

// TestListenCallbackAddress_Loopback asserts that the RFC 8252 loopback
// callback server binds to 127.0.0.1 (not 0.0.0.0 or any LAN address)
// (BRWS-02, D-05 IMMUTABLE).
func TestListenCallbackAddress_Loopback(t *testing.T) {
	t.Skip("TODO: internal/browser not yet implemented — Wave 3")
}

// TestListenCallbackStateMismatch asserts that a callback request carrying a
// mismatched OAuth state parameter is rejected (BRWS-02, T-35-OAuth-csrf).
// The comparison must use crypto/subtle.ConstantTimeCompare to prevent
// timing-based state forgery.
func TestListenCallbackStateMismatch(t *testing.T) {
	t.Skip("TODO: internal/browser not yet implemented — Wave 3")
}

// TestListenCallbackPKCE asserts that a callback presenting the wrong
// code_verifier is rejected (BRWS-02, T-35-OAuth-pkce). S256 verification
// must happen before the auth code is accepted.
func TestListenCallbackPKCE(t *testing.T) {
	t.Skip("TODO: internal/browser not yet implemented — Wave 3")
}

// TestListenCallbackTimeout asserts that context cancellation / timeout causes
// the loopback callback server to shut down cleanly via http.Server.Shutdown
// and return a context error to the caller (BRWS-02, T-35-OAuth-dos).
func TestListenCallbackTimeout(t *testing.T) {
	t.Skip("TODO: internal/browser not yet implemented — Wave 3")
}

// TestListenCallbackHappyPath wires a fake authorize endpoint via
// httptest.Server and runs the full loopback callback happy path: open URL,
// redirect browser to callback, receive auth code, shut down server
// (BRWS-02, T-35-OAuth-pkce end-to-end).
func TestListenCallbackHappyPath(t *testing.T) {
	t.Skip("TODO: internal/browser not yet implemented — Wave 3")
}
