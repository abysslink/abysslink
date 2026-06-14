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

package ssh

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCAProvider is a test double for CAProvider. caErr, when non-nil, exercises
// the fail-safe path (CAPublicKey error → legacy drop-in, no directives).
type fakeCAProvider struct {
	caLine  string
	caErr   error
	serials []uint64
}

func (f fakeCAProvider) CAPublicKey(_ context.Context) (string, error) {
	return f.caLine, f.caErr
}

func (f fakeCAProvider) RevokedSerials() []uint64 { return f.serials }

// Compile-time assertion that the fake satisfies the interface.
var _ CAProvider = fakeCAProvider{}

// TestRenderKRLSpec pins the deterministic, sorted spec render: regardless of
// input order the output is sorted ascending and byte-identical across calls.
func TestRenderKRLSpec(t *testing.T) {
	cases := []struct {
		name string
		in   []uint64
		want string
	}{
		{
			name: "two_serials_unsorted",
			in:   []uint64{7, 5},
			want: krlSpecHeader + "serial: 5\nserial: 7\n",
		},
		{
			name: "already_sorted",
			in:   []uint64{1, 2, 3},
			want: krlSpecHeader + "serial: 1\nserial: 2\nserial: 3\n",
		},
		{
			name: "single",
			in:   []uint64{42},
			want: krlSpecHeader + "serial: 42\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderKRLSpec(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}

	// Determinism: the same unsorted input renders byte-identical output twice,
	// and renderKRLSpec must not mutate its input slice.
	in := []uint64{9, 3, 6, 1}
	first := renderKRLSpec(in)
	second := renderKRLSpec(in)
	assert.Equal(t, first, second, "renderKRLSpec must be the deterministic idempotency anchor")
	assert.Equal(t, []uint64{9, 3, 6, 1}, in, "renderKRLSpec must not mutate its input")
	assert.Equal(t, krlSpecHeader+"serial: 1\nserial: 3\nserial: 6\nserial: 9\n", first)
}

// TestEmptyKRLSpec asserts nil and empty slices both yield the header alone —
// a valid empty spec (yielding a valid empty KRL revoking nothing).
func TestEmptyKRLSpec(t *testing.T) {
	for _, in := range [][]uint64{nil, {}} {
		got := renderKRLSpec(in)
		require.Equal(t, krlSpecHeader, got, "empty serial set must render the header alone")
		assert.Equal(t, 0, strings.Count(got, "serial:"), "empty spec must contain no serial lines")
	}
}
