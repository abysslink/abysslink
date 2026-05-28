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
	"testing"

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

func TestTmuxConfContents(t *testing.T) {
	assert.Contains(t, tmuxConf, "abysslink managed")
	assert.Contains(t, tmuxConf, "tmux-plugins/tpm")
	assert.Contains(t, tmuxConf, "@continuum-restore 'on'")
	assert.Contains(t, tmuxConf, "@continuum-save-interval '15'", "continuum must save every 15 minutes")
	assert.Contains(t, tmuxConf, "run '~/.tmux/plugins/tpm/tpm'")
}
