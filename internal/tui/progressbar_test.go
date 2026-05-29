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

package tui_test

import (
	"testing"

	"github.com/abysslink/abysslink/internal/tui"
	"github.com/stretchr/testify/assert"
)

// TestPlainBar_Format asserts that PlainBar(3, 9) returns a string containing
// "[3/9]".
func TestPlainBar_Format(t *testing.T) {
	out := tui.PlainBar(3, 9)
	assert.Contains(t, out, "[3/9]")
}

// TestPlainBar_Zero asserts PlainBar(0, 5) returns "[0/5]".
func TestPlainBar_Zero(t *testing.T) {
	out := tui.PlainBar(0, 5)
	assert.Contains(t, out, "[0/5]")
}

// TestPlainBar_Full asserts PlainBar(n, n) returns "[N/N]" indicating completion.
func TestPlainBar_Full(t *testing.T) {
	out := tui.PlainBar(5, 5)
	assert.Contains(t, out, "[5/5]")
}
