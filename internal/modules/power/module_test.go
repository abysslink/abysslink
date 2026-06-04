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

package power

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplyDarwin_AlreadyDisabledShortCircuit asserts that applyDarwin makes zero
// RunInteractive calls (does not invoke sudo pmset) when pmset -g already shows
// sleep=0. The short-circuit avoids a redundant sudo password prompt when init
// already disabled sleep in runSecurityFixes.
func TestApplyDarwin_AlreadyDisabledShortCircuit(t *testing.T) {
	// pmset -g → sleep is already 0 (sleep prevented by powerd)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: " sleep  0 (sleep prevented by powerd)\n", ExitCode: 0}},
	)
	cfg := config.Defaults()
	cfg.Power.ClosedLidAC = "keep-awake"
	m := New(modules.Deps{Runner: runner, Cfg: cfg})

	err := m.applyDarwin(context.Background())
	require.NoError(t, err)

	// No RunInteractive calls — sudo pmset must not have been invoked.
	assert.Empty(t, runner.RunInteractiveCalls(),
		"applyDarwin must not invoke sudo pmset when sleep is already disabled")
}

// TestApplyDarwin_SleepEnabledRunsSudo asserts that applyDarwin invokes
// RunInteractive with the sudo pmset argv when sleep is enabled.
func TestApplyDarwin_SleepEnabledRunsSudo(t *testing.T) {
	// Call 1: pmset -g → sleep enabled (non-zero)
	// Call 2: sudo pmset → success
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: " sleep         10\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	cfg := config.Defaults()
	cfg.Power.ClosedLidAC = "keep-awake"
	m := New(modules.Deps{Runner: runner, Cfg: cfg})

	err := m.applyDarwin(context.Background())
	require.NoError(t, err)

	interactive := runner.RunInteractiveCalls()
	require.Len(t, interactive, 1, "expected exactly one RunInteractive call for sudo pmset")
	assert.Equal(t, []string{"sudo", "pmset", "-c", "sleep", "0", "disksleep", "0"}, interactive[0])
}

func TestACSleepState(t *testing.T) {
	cases := []struct {
		name      string
		output    string
		wantValue int
		wantFound bool
	}{
		{"sleep_zero", " sleep         0\n", 0, true},
		{"sleep_ten", " sleep         10\n", 10, true},
		{"annotated_zero", " sleep  0 (sleep prevented by powerd)\n", 0, true},
		{"disksleep_only", " disksleep     10\n", 0, false},
		{"empty", "", 0, false},
		{"no_sleep_line", "autopoweroffdelay 28800\n", 0, false},
		// pmset -g custom emits both blocks; only the AC value must be read.
		{
			"ac_zero_battery_ten",
			"AC Power:\n sleep 0\nBattery Power:\n sleep 10\n",
			0, true,
		},
		{
			"ac_ten_battery_zero",
			"AC Power:\n sleep 10\nBattery Power:\n sleep 0\n",
			10, true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, found := acSleepState(tc.output)
			assert.Equal(t, tc.wantFound, found)
			if found {
				assert.Equal(t, tc.wantValue, value)
			}
		})
	}
}
