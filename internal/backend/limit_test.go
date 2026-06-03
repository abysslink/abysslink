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

// Package backend — internal tests for readLimited (unexported helper).
package backend

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadLimited_UnderLimit verifies that a body smaller than n is returned
// intact without error.
func TestReadLimited_UnderLimit(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 100)
	r := io.NopCloser(bytes.NewReader(data))

	got, err := readLimited(r, maxBackendBody)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

// TestReadLimited_ExactLimit verifies that a body of exactly maxBackendBody
// bytes is accepted (no error).
func TestReadLimited_ExactLimit(t *testing.T) {
	data := bytes.Repeat([]byte("B"), int(maxBackendBody))
	r := io.NopCloser(bytes.NewReader(data))

	got, err := readLimited(r, maxBackendBody)
	require.NoError(t, err)
	assert.Equal(t, int(maxBackendBody), len(got))
}

// TestReadLimited_OverLimit verifies that a body of maxBackendBody+1 bytes
// returns an error whose message contains "exceeded".
func TestReadLimited_OverLimit(t *testing.T) {
	data := bytes.Repeat([]byte("C"), int(maxBackendBody)+1)
	r := io.NopCloser(bytes.NewReader(data))

	got, err := readLimited(r, maxBackendBody)
	require.Error(t, err, "oversized body must return an error")
	assert.Nil(t, got, "returned data must be nil on overflow")
	assert.Contains(t, err.Error(), "exceeded",
		"error message must contain 'exceeded'")
}

// TestReadLimited_Empty verifies that an empty body is handled gracefully
// (returns empty slice, no error).
func TestReadLimited_Empty(t *testing.T) {
	r := io.NopCloser(bytes.NewReader(nil))

	got, err := readLimited(r, maxBackendBody)
	require.NoError(t, err)
	assert.Empty(t, got)
}
