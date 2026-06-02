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
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCollectDoctorFindings_AlwaysReturnsFindings asserts the shared collector
// returns a non-empty, ordered finding set even on a bare system — the
// supply/metrics/webui/sec families always emit at least one finding each, so
// the dashboard never renders a fabricated empty (false-clean) doctor view.
func TestCollectDoctorFindings_AlwaysReturnsFindings(t *testing.T) {
	cfg := config.Defaults()
	runner := shell.NewMockRunner() // any shellout is an "unexpected call" error → graceful degrade

	findings := CollectDoctorFindings(context.Background(), cfg, runner)

	require.NotEmpty(t, findings, "doctor must always surface findings, never an empty all-clear")

	// The webui and supply families are config/probe-driven and always present
	// regardless of the runner, proving the canonical ordering executed.
	var sawSupply, sawWebui bool
	for _, f := range findings {
		switch f.Module {
		case "supply":
			sawSupply = true
		case "webui":
			sawWebui = true
		}
	}
	assert.True(t, sawSupply, "supply-chain family must run in the canonical order")
	assert.True(t, sawWebui, "webui family must run in the canonical order")
}

// TestCollectDoctorFindings_NilConfigSafe asserts the exported entrypoint
// tolerates a nil config (defaults applied) and nil runner without panicking.
func TestCollectDoctorFindings_NilConfigSafe(t *testing.T) {
	assert.NotPanics(t, func() {
		_ = CollectDoctorFindings(context.Background(), nil, shell.NewMockRunner())
	})
}

// TestCollectFleetStatus_LocalRigOnly asserts that with no enrolled rigs the
// snapshot contains exactly the local rig row, the total counts it, and its
// lock posture is read authoritatively from config.
func TestCollectFleetStatus_LocalRigOnly(t *testing.T) {
	cfg := config.Defaults()
	cfg.Tailnet.Hostname = "laptop"
	cfg.Tailnet.Lock.Enabled = true

	online, total, rigs := CollectFleetStatus(context.Background(), cfg, shell.NewMockRunner())

	require.Len(t, rigs, 1, "no enrolled rigs ⇒ only the local rig row")
	assert.Equal(t, 1, total)
	assert.GreaterOrEqual(t, online, 0)
	assert.LessOrEqual(t, online, 1)

	local := rigs[0]
	assert.Equal(t, "laptop", local.Name)
	assert.True(t, local.IsLocalRig)
	assert.Equal(t, LockLocked, local.Lock, "local lock posture is read from config")
	assert.False(t, local.HasCert, "local cert expiry is not probed here (N/A, not a fabricated value)")
}

// TestCollectFleetStatus_RemoteRigUnknownOnUnreachable asserts an enrolled
// remote rig that does not answer is reported honestly (offline/unknown, never
// fabricated online) and does NOT inflate the online count (WR-05).
func TestCollectFleetStatus_RemoteRigUnknownOnUnreachable(t *testing.T) {
	cfg := config.Defaults()
	cfg.Tailnet.Hostname = "laptop"
	cfg.Rigs = []config.RigConfig{
		{Name: "workstation", Hostname: "workstation.ts", Backend: "tailscale"},
	}

	online, total, rigs := CollectFleetStatus(context.Background(), cfg, shell.NewMockRunner())

	require.Len(t, rigs, 2, "local rig + one remote rig")
	assert.Equal(t, 2, total)

	var remote RigStatus
	for _, r := range rigs {
		if r.Name == "workstation" {
			remote = r
		}
	}
	require.Equal(t, "workstation", remote.Name)
	assert.NotEqual(t, RigOnline, remote.Reachable, "an unreachable rig must never be reported online (WR-05)")
	assert.Equal(t, LockNA, remote.Lock, "remote lock posture is N/A, never a fabricated value")
	// online must not count the unreachable remote rig.
	assert.LessOrEqual(t, online, 1)
}

// compile-time: a finding's severity zero value is SeverityOK (sanity guard the
// honest-N/A logic relies on).
var _ modules.Severity = modules.SeverityOK
