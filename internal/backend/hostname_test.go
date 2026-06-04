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

package backend_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// newNetBirdHostnameMockServer returns a minimal httptest.Server that serves
// just enough for the NetBird adapter to initialise. It is only used for the
// hostname-rejection test — no real HTTP traffic should reach it because the
// ValidateHostname guard fires before any runner.Run or HTTP call.
func newNetBirdHostnameMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any call reaching here means the guard did NOT fire — fail loud.
		http.Error(w, "unexpected call to mock server — hostname guard should have fired first", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// netbirdHostnameCfg returns a *config.Config for the hostname guard test:
// backend.type=netbird with a valid server URL so the adapter constructs OK.
// AcceptNoSSHCheck is set to true to bypass the D-04 gate in tests.
func netbirdHostnameCfg(serverURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = serverURL
	cfg.Server.NetBird.AcceptNoSSHCheck = true
	return cfg
}

// TestUp_BadHostname_RejectsArgv asserts that both the Headscale and NetBird
// Up implementations return an error containing "unsafe characters" when given
// a hostname with shell-injection chars (leading "--"), and do NOT pass that
// value to runner.Run as a --hostname= flag (D-03, NET-03).
//
// RED: This test FAILS until plan 25-02 Task 2 adds config.ValidateHostname
// guards in headscale.Up and netbird.Up before args construction.
func TestUp_BadHostname_RejectsArgv(t *testing.T) {
	unsafeHostname := "--inject-flag"

	t.Run("headscale", func(t *testing.T) {
		var pushed atomic.Int32
		srv := newHeadscaleMockServer(t, &pushed, nil)
		defer srv.Close()

		b, err := backend.New(headscaleCfg(srv.URL), shell.NewMockRunner())
		if err != nil {
			t.Fatalf("backend.New: %v", err)
		}

		t.Setenv("ABYSSLINK_HS_PREAUTHKEY", "test-key")

		upErr := b.Up(context.Background(), backend.UpOpts{
			Hostname: unsafeHostname,
		})
		if upErr == nil {
			t.Fatal("expected headscale Up to return error for unsafe hostname, got nil — " +
				"RED: config.ValidateHostname guard not yet wired in headscale.Up (fix in plan 25-02 Task 2)")
		}
		if !strings.Contains(upErr.Error(), "unsafe characters") {
			t.Errorf("expected error to contain %q, got: %v", "unsafe characters", upErr)
		}
	})

	t.Run("netbird", func(t *testing.T) {
		srv := newNetBirdHostnameMockServer(t)
		defer srv.Close()

		b, err := backend.New(netbirdHostnameCfg(srv.URL), shell.NewMockRunner())
		if err != nil {
			t.Fatalf("backend.New: %v", err)
		}

		t.Setenv("ABYSSLINK_NB_API_KEY", "test-key")
		t.Setenv("ABYSSLINK_NB_SETUP_KEY", "test-setup-key")

		upErr := b.Up(context.Background(), backend.UpOpts{
			Hostname: unsafeHostname,
		})
		if upErr == nil {
			t.Fatal("expected netbird Up to return error for unsafe hostname, got nil — " +
				"RED: config.ValidateHostname guard not yet wired in netbird.Up (fix in plan 25-02 Task 2)")
		}
		if !strings.Contains(upErr.Error(), "unsafe characters") {
			t.Errorf("expected error to contain %q, got: %v", "unsafe characters", upErr)
		}
	})
}
