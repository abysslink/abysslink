//go:build darwin

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

package attest

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const iBridgeFullJSON = `{"SPiBridgeDataType":[{"ibridge_secure_boot":"Full Security","ibridge_sb_sip":"Enabled","ibridge_sb_ssv":"Enabled"}]}`

// TestCollect_Darwin scripts the full macOS probe set through MockRunner:
// csrutil status, csrutil authenticated-root status, system_profiler.
func TestCollect_Darwin(t *testing.T) {
	ctx := context.Background()

	t.Run("all_green_is_verified", func(t *testing.T) {
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "System Integrity Protection status: enabled.\n", ExitCode: 0}},
			shell.Call{Result: shell.Result{Stdout: "Authenticated Root status: enabled\n", ExitCode: 0}},
			shell.Call{Result: shell.Result{Stdout: iBridgeFullJSON, ExitCode: 0}},
		)
		rs := New(r).Collect(ctx)
		require.Len(t, rs, 2)
		assert.Equal(t, "sip", rs[0].Probe)
		assert.Equal(t, StateOK, rs[0].State)
		assert.Equal(t, "secureboot", rs[1].Probe)
		assert.Equal(t, StateOK, rs[1].State)
		assert.Equal(t, "verified", Summarize(rs))
		assert.True(t, r.Done())
	})

	t.Run("sip_disabled_is_weakened", func(t *testing.T) {
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "System Integrity Protection status: disabled.\n", ExitCode: 0}},
			shell.Call{Result: shell.Result{Stdout: "Authenticated Root status: enabled\n", ExitCode: 0}},
			shell.Call{Result: shell.Result{Stdout: iBridgeFullJSON, ExitCode: 0}},
		)
		rs := New(r).Collect(ctx)
		assert.Equal(t, StateFail, rs[0].State)
		assert.Equal(t, "weakened", Summarize(rs))
	})

	t.Run("tools_missing_is_unverified", func(t *testing.T) {
		r := shell.NewMockRunner(
			shell.Call{Err: assert.AnError},
			shell.Call{Err: assert.AnError},
			shell.Call{Err: assert.AnError},
		)
		rs := New(r).Collect(ctx)
		for _, res := range rs {
			assert.Equal(t, StateWarn, res.State, "missing tools never yield green")
		}
		assert.Equal(t, "unverified", Summarize(rs))
	})

	t.Run("worst_wins_within_secureboot", func(t *testing.T) {
		r := shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "System Integrity Protection status: enabled.\n", ExitCode: 0}},
			shell.Call{Result: shell.Result{Stdout: "Authenticated Root status: disabled\n", ExitCode: 0}}, // FAIL
			shell.Call{Result: shell.Result{Stdout: iBridgeFullJSON, ExitCode: 0}},                         // OK
		)
		rs := New(r).Collect(ctx)
		assert.Equal(t, StateFail, rs[1].State, "FAIL beats OK within the secureboot probe")
	})
}
