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

package hwkey

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSSHVersion_NumericTuple(t *testing.T) {
	cases := []struct {
		name         string
		line         string
		major, minor int
		wantErr      bool
	}{
		{"macos_10_2", "OpenSSH_10.2p1, LibreSSL 3.3.6", 10, 2, false},
		{"ubuntu_vendor_suffix", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024", 9, 6, false},
		{"openbsd_no_pN", "OpenSSH_9.9, LibreSSL 4.0.0", 9, 9, false},
		{"exactly_floor", "OpenSSH_10.0p2", 10, 0, false},
		{"garbage", "Secure Shell 3000", 0, 0, true},
		{"empty", "", 0, 0, true},
		{"prefix_not_at_offset_zero", "debug1: OpenSSH_10.0p1", 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			major, minor, err := ParseSSHVersion(tc.line)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrParse, "a parse miss must be ErrParse (never assume-modern)")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.major, major)
			assert.Equal(t, tc.minor, minor)
		})
	}
}

// TestMeetsFloor_NumericNotLexical is the named regression for the
// string-compare bug: (10,0) must beat (9,9) numerically ("10" < "9"
// lexically).
func TestMeetsFloor_NumericNotLexical(t *testing.T) {
	assert.True(t, MeetsFloor(10, 0), "(10,0) meets the (10,0) floor")
	assert.True(t, MeetsFloor(10, 2))
	assert.True(t, MeetsFloor(11, 0))
	assert.False(t, MeetsFloor(9, 9), "(9,9) is below (10,0) — numeric, not lexical")
	assert.False(t, MeetsFloor(9, 0))
	assert.False(t, MeetsFloor(8, 2))
}
