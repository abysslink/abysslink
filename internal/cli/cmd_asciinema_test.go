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

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAsciinemaRec_RequiresInteractiveTTY verifies that a non-interactive
// context (e.g. non-TTY stdin) is rejected before any prompt or runner call,
// so the credential warning can never be silently skipped (HARD FLOOR).
func TestAsciinemaRec_RequiresInteractiveTTY(t *testing.T) {
	promptCalled := false
	prompt := func(_ context.Context, _ string) error {
		promptCalled = true
		return nil
	}
	r := shell.NewMockRunner() // no scripted calls: any RunInteractive call fails the test

	err := runAsciinemaRec(context.Background(), false, prompt, r, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal required")
	assert.False(t, promptCalled, "prompt must not be shown in a non-interactive context")
}

// TestAsciinemaRec_RejectsYesFlag verifies that --yes (which makes interactive()
// return false) also produces the terminal-required error: --yes is
// non-interactive, so the warning cannot be shown.
func TestAsciinemaRec_RejectsYesFlag(t *testing.T) {
	// interactive(yes=true, jsonOut=false) == false, mirroring the --yes path.
	isInteractive := interactive(true, false)
	require.False(t, isInteractive)

	r := shell.NewMockRunner()
	err := runAsciinemaRec(context.Background(), isInteractive, nil, r, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal required")
}

// TestAsciinemaRec_NilPromptFailsClosed verifies that an interactive context
// with no wired prompt errors rather than proceeding to record without the
// warning (I-01 fail-closed correction).
func TestAsciinemaRec_NilPromptFailsClosed(t *testing.T) {
	r := shell.NewMockRunner()
	err := runAsciinemaRec(context.Background(), true, nil, r, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential warning unavailable")
}

// TestAsciinemaRec_PromptCalledBeforeExec verifies that, in an interactive
// context, the credential warning prompt is shown before asciinema rec is run.
func TestAsciinemaRec_PromptCalledBeforeExec(t *testing.T) {
	order := []string{}
	prompt := func(_ context.Context, msg string) error {
		assert.Contains(t, msg, "CREDENTIALS")
		order = append(order, "prompt")
		return nil
	}
	r := shell.NewMockRunner(shell.Call{})

	err := runAsciinemaRec(context.Background(), true, prompt, r, []string{"demo.cast"})
	require.NoError(t, err)

	calls := r.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "asciinema", calls[0].Name)
	assert.Equal(t, []string{"rec", "demo.cast"}, calls[0].Args)
	require.Equal(t, []string{"prompt"}, order, "prompt must be called before asciinema rec")
}
