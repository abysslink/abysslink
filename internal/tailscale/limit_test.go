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

package tailscale

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReadLimited_OverLimit asserts that readLimited returns an error when
// the body exceeds the cap (N+1 sentinel detects overflow).
func TestReadLimited_OverLimit(t *testing.T) {
	body := bytes.Repeat([]byte("x"), int(maxAdminBody)+1)
	rc := io.NopCloser(bytes.NewReader(body))
	_, err := readLimited(rc, maxAdminBody)
	require.Error(t, err, "expected error when body exceeds limit")
	require.True(t, strings.Contains(err.Error(), "exceeded"),
		"error should contain 'exceeded', got: %v", err)
}

// TestReadLimited_UnderLimit asserts that readLimited returns the full data
// without error when the body is exactly at the cap.
func TestReadLimited_UnderLimit(t *testing.T) {
	body := bytes.Repeat([]byte("y"), int(maxAdminBody))
	rc := io.NopCloser(bytes.NewReader(body))
	data, err := readLimited(rc, maxAdminBody)
	require.NoError(t, err)
	require.Equal(t, int(maxAdminBody), len(data), "expected all bytes returned at cap")
}

// TestReadLimited_Empty asserts that readLimited handles an empty body gracefully.
func TestReadLimited_Empty(t *testing.T) {
	rc := io.NopCloser(bytes.NewReader(nil))
	data, err := readLimited(rc, maxAdminBody)
	require.NoError(t, err)
	require.True(t, len(data) == 0, "expected empty result for empty body")
}
