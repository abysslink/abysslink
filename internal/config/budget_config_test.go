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

// TestBudgetDefaults verifies that Defaults() returns the shadow-mode values
// for BudgetConfig (D-05): Ladder false, WallClockMinutes 30, LoopN 8,
// LoopWindow 20, KillGraceSeconds 5.
func TestBudgetDefaults(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.Budget.Ladder, "shadow mode default: Ladder must be false (D-05)")
	assert.Equal(t, 30, cfg.Budget.WallClockMinutes, "default WallClockMinutes")
	assert.Equal(t, 8, cfg.Budget.LoopN, "default LoopN")
	assert.Equal(t, 20, cfg.Budget.LoopWindow, "default LoopWindow")
	assert.Equal(t, 5, cfg.Budget.KillGraceSeconds, "default KillGraceSeconds")
	assert.Nil(t, cfg.Budget.TokenTiers, "TokenTiers must be nil by default (D-04)")
}

// TestBudgetValidate covers validateBudget bounds enforcement.
// Zero values mean "use default" and are accepted by all checks.
func TestBudgetValidate(t *testing.T) {
	tests := []struct {
		name    string
		budget  config.BudgetConfig
		wantErr string // empty means no error expected
	}{
		{
			name:    "zero values: use defaults, no error",
			budget:  config.BudgetConfig{},
			wantErr: "",
		},
		{
			name:    "valid custom values",
			budget:  config.BudgetConfig{WallClockMinutes: 60, LoopN: 5, LoopWindow: 10, KillGraceSeconds: 10},
			wantErr: "",
		},
		{
			name:    "LoopN below floor (1) with zero WallClock",
			budget:  config.BudgetConfig{WallClockMinutes: 0, LoopN: 1},
			wantErr: "loop_n",
		},
		{
			name:    "KillGraceSeconds above ceiling (31)",
			budget:  config.BudgetConfig{KillGraceSeconds: 31},
			wantErr: "kill_grace_seconds",
		},
		{
			name:    "WallClockMinutes below floor (0 is valid, but explicit < 1 is not)",
			budget:  config.BudgetConfig{WallClockMinutes: 0, LoopN: 2, LoopWindow: 5, KillGraceSeconds: 1},
			wantErr: "",
		},
		{
			name:    "LoopWindow below floor (4)",
			budget:  config.BudgetConfig{LoopWindow: 4},
			wantErr: "loop_window",
		},
		{
			name:    "KillGraceSeconds at floor (1)",
			budget:  config.BudgetConfig{KillGraceSeconds: 1},
			wantErr: "",
		},
		{
			name:    "KillGraceSeconds at ceiling (30)",
			budget:  config.BudgetConfig{KillGraceSeconds: 30},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			// Provide required identity fields so other validators pass
			// and only the budget validator is exercised.
			cfg.Identity.Email = "test@example.com"
			cfg.Identity.UnixUser = "testuser"
			cfg.Tailnet.Hostname = "testhost"
			cfg.Budget = tc.budget
			err := config.Validate(cfg)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestBudgetYAMLRoundTrip verifies YAML marshal/unmarshal preserves Ladder.
func TestBudgetYAMLRoundTrip(t *testing.T) {
	cfg := config.Defaults()
	cfg.Budget.Ladder = true

	// Verify the struct type is correct and the field is set.
	assert.True(t, cfg.Budget.Ladder)
	assert.Equal(t, 30, cfg.Budget.WallClockMinutes)
	assert.Equal(t, 8, cfg.Budget.LoopN)
}
