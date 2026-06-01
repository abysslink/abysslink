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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// TestCapabilityInterfaceLockstep asserts that the three sub-interface-backed
// Capabilities flags agree with the corresponding static interface type assertions.
//
// The three pairs are:
//
//	caps.Lock     ⟺  b.(backend.Locker)      — LockClient delegation
//	caps.AdminAPI ⟺  b.(backend.AdminAPI)     — AdminClient delegation
//	caps.ACL      ⟺  b.(backend.ACLManager)   — AdminClient+ACLEditor delegation
//
// SSHCheck, AuthKeys, FunnelRejection are advisory flags with NO sub-interface
// and are NOT part of the ⟺ assertion (RESEARCH Q5/Q6).
// This test will fail if any adapter incorrectly sets a capability flag without
// implementing the corresponding sub-interface (drift guard).
func TestCapabilityInterfaceLockstep(t *testing.T) {
	b, err := backend.New(tailscaleCfg(), shell.NewMockRunner())
	require.NoError(t, err)

	caps := b.Capabilities()

	_, isLocker := b.(backend.Locker)
	require.Equal(t, caps.Lock, isLocker,
		"caps.Lock must equal whether adapter implements backend.Locker")

	_, isAdmin := b.(backend.AdminAPI)
	require.Equal(t, caps.AdminAPI, isAdmin,
		"caps.AdminAPI must equal whether adapter implements backend.AdminAPI")

	_, isACL := b.(backend.ACLManager)
	require.Equal(t, caps.ACL, isACL,
		"caps.ACL must equal whether adapter implements backend.ACLManager")
}

// TestInvariant_NetBirdAdapter asserts the NB-01 sub-interface invariants for
// the netbirdAdapter:
//   - Does NOT implement Locker (no TKA)
//   - DOES implement AdminAPI
//   - DOES implement ACLManager
func TestInvariant_NetBirdAdapter(t *testing.T) {
	// Create a minimal mock server — invariant assertions don't make network calls.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)

	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = srv.URL

	b, err := backend.New(cfg, shell.NewMockRunner())
	require.NoError(t, err)

	// Must NOT implement Locker (caps.Lock=false invariant).
	_, isLocker := b.(backend.Locker)
	require.False(t, isLocker,
		"netbirdAdapter must NOT implement backend.Locker — Tailnet Lock not available on NetBird")

	// MUST implement AdminAPI (caps.AdminAPI=true invariant).
	_, isAdmin := b.(backend.AdminAPI)
	require.True(t, isAdmin,
		"netbirdAdapter must implement backend.AdminAPI")

	// MUST implement ACLManager (caps.ACL=true invariant).
	_, isACL := b.(backend.ACLManager)
	require.True(t, isACL,
		"netbirdAdapter must implement backend.ACLManager")

	// Lockstep: caps.Lock ⟺ isLocker, caps.AdminAPI ⟺ isAdmin, caps.ACL ⟺ isACL.
	caps := b.Capabilities()
	require.Equal(t, caps.Lock, isLocker,
		"netbird: caps.Lock must equal whether adapter implements Locker")
	require.Equal(t, caps.AdminAPI, isAdmin,
		"netbird: caps.AdminAPI must equal whether adapter implements AdminAPI")
	require.Equal(t, caps.ACL, isACL,
		"netbird: caps.ACL must equal whether adapter implements ACLManager")
}
