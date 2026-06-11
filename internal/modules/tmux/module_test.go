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

package tmux

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTmuxVersion(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
		wantErr      bool
	}{
		{"tmux 3.3a", 3, 3, false},
		{"tmux 3.0", 3, 0, false},
		{"tmux next-3.4", 0, 0, true}, // non-numeric major
		{"garbage", 0, 0, true},
	}
	for _, tc := range cases {
		maj, min, err := parseTmuxVersion(tc.in)
		if tc.wantErr {
			assert.Error(t, err, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.major, maj)
		assert.Equal(t, tc.minor, min)
	}
}

// TestVersionFloorIs32: the module floor must match the 3.2 capability floor
// `abysslink doctor` advertises for session-typed notifications (D-27) — two
// sources of truth for the same question must not diverge.
func TestVersionFloorIs32(t *testing.T) {
	assert.Equal(t, 3, minMajor)
	assert.Equal(t, 2, minMinor)

	cases := []struct {
		stdout   string
		wantWarn bool
	}{
		{"tmux 3.0\n", true},  // below the doctor floor
		{"tmux 3.1c\n", true}, // below the doctor floor
		{"tmux 3.2\n", false},
		{"tmux 3.2a\n", false},
		{"tmux 3.3a\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.stdout, func(t *testing.T) {
			r := shell.NewMockRunner(
				shell.Call{Result: shell.Result{ExitCode: 0, Stdout: tc.stdout}},
			)
			m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
			findings, err := m.Detect(context.Background())
			require.NoError(t, err)

			var warned bool
			for _, f := range findings {
				if f.Check == "version" {
					warned = true
				}
			}
			assert.Equal(t, tc.wantWarn, warned, "stdout=%q", tc.stdout)
		})
	}
}

// TestBootstrapTPM_PinnedClone: the TPM clone argv must pin a release tag —
// never clone floating HEAD (supply chain).
func TestBootstrapTPM_PinnedClone(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.tmux/plugins/tpm → clone runs

	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}}, // git clone
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
	require.NoError(t, m.bootstrapTPM(context.Background()))
	require.True(t, r.Done())

	calls := r.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "git", calls[0].Name)
	args := calls[0].Args
	var pinned bool
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--branch" && args[i+1] == tpmVersion {
			pinned = true
		}
	}
	assert.True(t, pinned, "git clone must pin --branch %s, got argv %v", tpmVersion, args)
}

func TestTmuxConfContents(t *testing.T) {
	assert.Contains(t, tmuxConf, "abysslink managed")
	assert.Contains(t, tmuxConf, "tmux-plugins/tpm")
	assert.Contains(t, tmuxConf, "@continuum-restore 'on'")
	assert.Contains(t, tmuxConf, "@continuum-save-interval '15'", "continuum must save every 15 minutes")
	assert.Contains(t, tmuxConf, "run '~/.tmux/plugins/tpm/tpm'")
}
