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

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
)

// TestDeadmanConfig_DefaultsOff asserts the dead-man switch is OPT-IN and ships
// OFF (32-CONTEXT.md). A default config must never launch a lockdown timer.
func TestDeadmanConfig_DefaultsOff(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.Deadman.Enabled, "dead-man switch must default OFF (opt-in)")
}

// TestDeadmanConfig_ZeroIntervalResolvesTo24h asserts the locked 24h default:
// a zero/unset IntervalHours resolves to 24 at runtime.
func TestDeadmanConfig_ZeroIntervalResolvesTo24h(t *testing.T) {
	d := config.DeadmanConfig{Enabled: true, IntervalHours: 0}
	assert.Equal(t, 24, d.ResolvedIntervalHours())
	assert.Equal(t, 24, config.DeadmanDefaultIntervalHours)

	// An explicit interval is honoured verbatim.
	d2 := config.DeadmanConfig{Enabled: true, IntervalHours: 6}
	assert.Equal(t, 6, d2.ResolvedIntervalHours())
}

// TestDeadmanConfig_ValidateRejectsSubFloor asserts Validate rejects an ENABLED
// switch with a sub-floor (below 1h) interval, but accepts zero (→24h default)
// and accepts any interval under a DISABLED switch.
func TestDeadmanConfig_ValidateRejectsSubFloor(t *testing.T) {
	base := config.Defaults()
	base.Identity.Email = "a@b.com"
	base.Identity.UnixUser = "user"
	base.Tailnet.Hostname = "rig"

	// Enabled + sub-floor interval (0 < n < 1h floor is impossible in hours, so
	// the floor is expressed as < 1 → only negative; use Validate's >=1 contract
	// by setting a negative interval which a hand-edited YAML could carry).
	bad := *base
	bad.Deadman = config.DeadmanConfig{Enabled: true, IntervalHours: -1}
	require.Error(t, config.Validate(&bad), "enabled switch with a sub-floor interval must be rejected")

	// Enabled + zero interval is valid (resolves to 24h).
	okZero := *base
	okZero.Deadman = config.DeadmanConfig{Enabled: true, IntervalHours: 0}
	require.NoError(t, config.Validate(&okZero))

	// Enabled + at-floor interval is valid.
	okFloor := *base
	okFloor.Deadman = config.DeadmanConfig{Enabled: true, IntervalHours: 1}
	require.NoError(t, config.Validate(&okFloor))

	// Disabled switch never constrains the interval (a stale value is harmless).
	disabled := *base
	disabled.Deadman = config.DeadmanConfig{Enabled: false, IntervalHours: -99}
	require.NoError(t, config.Validate(&disabled))
}
