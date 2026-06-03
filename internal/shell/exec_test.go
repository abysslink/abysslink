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

// Package shell — internal tests for limitedWriter (unexported type).
package shell

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecRunner_StdoutCapExceeded verifies that limitedWriter returns an error
// (containing "exceeded") when the total write would exceed the cap. This is an
// internal test (package shell, not shell_test) because limitedWriter is unexported.
func TestExecRunner_StdoutCapExceeded(t *testing.T) {
	var buf bytes.Buffer
	lw := &limitedWriter{buf: &buf, cap: 10}

	// Write exactly at the cap — must succeed.
	n, err := lw.Write([]byte("0123456789"))
	require.NoError(t, err)
	assert.Equal(t, 10, n)

	// Write one more byte — must fail with an error containing "exceeded".
	n, err = lw.Write([]byte("X"))
	require.Error(t, err, "write beyond cap must return an error")
	assert.Equal(t, 0, n, "bytes written must be 0 on overflow")
	assert.Contains(t, err.Error(), "exceeded")
}

// TestLimitedWriter_WriteUnderCap verifies that writes within the cap accumulate
// correctly in the underlying buffer.
func TestLimitedWriter_WriteUnderCap(t *testing.T) {
	var buf bytes.Buffer
	lw := &limitedWriter{buf: &buf, cap: maxSubprocessOutput}

	_, err := lw.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, "hello", buf.String())
}
