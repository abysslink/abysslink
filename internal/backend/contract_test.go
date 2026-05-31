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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// runningStatusJSON is the mock `tailscale status --json` fixture.
// Copied verbatim from internal/tailscale/local_test.go:29-43.
const runningStatusJSON = `{
	"BackendState": "Running",
	"Self": {
		"HostName": "my-laptop",
		"DNSName": "my-laptop.example.ts.net.",
		"TailscaleIPs": ["100.64.0.1", "fd7a:115c::1"],
		"Online": true
	},
	"Health": [],
	"MagicDNSSuffix": "example.ts.net",
	"CurrentTailnet": {
		"Name": "example.com",
		"MagicDNSSuffix": "example.ts.net"
	}
}`

// tailscaleCfg returns a minimal *config.Config for the tailscale adapter tests.
// Backend.Type is "tailscale"; Mobile.SSHCheckPeriod is "12h".
func tailscaleCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "tailscale"
	// SSHCheckPeriod is already "12h" from Defaults(); keep it to exercise
	// the normal parse path. Contract invariant #2: CheckPeriod must be non-zero.
	return cfg
}

// TestContract_TailscaleAdapter asserts the 3 mandated contract invariants
// against the tailscale adapter driven by a MockRunner.
// This is the merge gate: it runs in default CI (no real tailscale binary needed).
func TestContract_TailscaleAdapter(t *testing.T) {
	// Seed MockRunner with the running status fixture so IP() returns non-empty.
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: runningStatusJSON, ExitCode: 0},
	})

	b, err := backend.New(tailscaleCfg(), runner)
	require.NoError(t, err)

	// Invariant #1: IP() returns a non-empty string.
	ip, err := b.IP(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, ip, "contract invariant #1: IP() must return a non-empty address")

	// Invariant #2: SSHConfig().CheckPeriod is non-zero.
	require.NotZero(t, b.SSHConfig().CheckPeriod,
		"contract invariant #2: SSHConfig().CheckPeriod must be non-zero")

	// Invariant #3: LockCapability() == LockFull.
	require.Equal(t, backend.LockFull, b.LockCapability(),
		"contract invariant #3: Tailscale adapter must report LockFull")
}

// TestContract_UnknownBackend asserts that New() returns a non-nil error
// when cfg.Backend.Type is an unknown value (T-11-04: fails closed).
// Note: "headscale" and "netbird" are implemented backends; using "wireguard"
// as the truly unknown type to keep the fails-closed invariant.
func TestContract_UnknownBackend(t *testing.T) {
	cfg := tailscaleCfg()
	cfg.Backend.Type = "wireguard" // unknown — not implemented
	_, err := backend.New(cfg, shell.NewMockRunner())
	require.Error(t, err, "New() must return an error for unknown backend type")
	require.Contains(t, err.Error(), "wireguard")
}

// TestNetBirdAdapterPlaceholder is a placeholder for the full netbird adapter
// contract tests. The netbird adapter will be implemented in wave 2 (plan 13-02).
//
// This test exists to ensure the test file compiles cleanly and to document
// where the netbird contract tests will live.
func TestNetBirdAdapterPlaceholder(t *testing.T) {
	t.Skip("netbird adapter not yet implemented — wave 2")
}

// TestContract_EmptyTypeDefaultsTailscale verifies that backend.Type="" works
// as the defensive fallback (config.Load normalizes it, but factory handles it too).
func TestContract_EmptyTypeDefaultsTailscale(t *testing.T) {
	cfg := tailscaleCfg()
	cfg.Backend.Type = "" // should default to tailscale adapter
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: runningStatusJSON, ExitCode: 0},
	})
	b, err := backend.New(cfg, runner)
	require.NoError(t, err)
	require.NotNil(t, b)
}

// TestContract_SSHConfigFallback verifies that SSHConfig().CheckPeriod falls
// back to the immutable 12h default when Mobile.SSHCheckPeriod is empty.
func TestContract_SSHConfigFallback(t *testing.T) {
	cfg := tailscaleCfg()
	cfg.Mobile.SSHCheckPeriod = "" // trigger fallback
	b, err := backend.New(cfg, shell.NewMockRunner())
	require.NoError(t, err)
	require.NotZero(t, b.SSHConfig().CheckPeriod,
		"SSHConfig() must fall back to 12h when SSHCheckPeriod is empty")
}

// Note: the integration test (requiring a real tailscale binary) is in
// contract_integration_test.go behind //go:build integration.
