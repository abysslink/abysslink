//go:build linux

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

// TestCollect_Linux scripts the Linux probe set: efivar fixtures via the
// EFIVarsDir seam + tpm2_pcrread through MockRunner.
func TestCollect_Linux(t *testing.T) {
	ctx := context.Background()

	t.Run("secure_boot_and_tpm_ok_is_verified", func(t *testing.T) {
		p := efiFixture(t, efiVar(1), efiVar(0))
		p.Runner = shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: pcrRuntimeShape, ExitCode: 0}})
		rs := p.Collect(ctx)
		require.Len(t, rs, 2)
		assert.Equal(t, "secureboot", rs[0].Probe)
		assert.Equal(t, StateOK, rs[0].State)
		assert.Equal(t, "tpm", rs[1].Probe)
		assert.Equal(t, StateOK, rs[1].State)
		assert.Equal(t, "verified", Summarize(rs))
	})

	t.Run("secure_boot_disabled_is_weakened", func(t *testing.T) {
		p := efiFixture(t, efiVar(0), efiVar(0))
		p.Runner = shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: pcrRuntimeShape, ExitCode: 0}})
		rs := p.Collect(ctx)
		assert.Equal(t, StateFail, rs[0].State)
		assert.Equal(t, "weakened", Summarize(rs))
	})

	t.Run("tools_missing_is_unverified", func(t *testing.T) {
		p := efiFixture(t, nil, nil)
		p.Runner = shell.NewMockRunner(shell.Call{Err: assert.AnError})
		rs := p.Collect(ctx)
		for _, res := range rs {
			assert.Equal(t, StateWarn, res.State)
		}
		assert.Equal(t, "unverified", Summarize(rs))
	})
}
