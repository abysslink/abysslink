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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/tui"
)

// Confirm with yes=true bypasses the interactive prompt.
func TestConfirm_YesFlag(t *testing.T) {
	ok, err := tui.Confirm(context.Background(), "Do the thing?", true)
	require.NoError(t, err)
	assert.True(t, ok)
}

// Select with yes=true and a single option returns it immediately.
func TestSelect_YesFlagSingleOption(t *testing.T) {
	result, err := tui.Select(context.Background(), "Pick one", []string{"only"}, true)
	require.NoError(t, err)
	assert.Equal(t, "only", result)
}

// Select with yes=true but multiple options still requires interaction — so we
// test only that the function signature compiles and that calling with a
// cancelled context returns an error.
func TestSelect_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tui.Select(ctx, "Pick", []string{"a", "b"}, false)
	require.Error(t, err)
}

// Confirm with a cancelled context returns an error.
func TestConfirm_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tui.Confirm(ctx, "Confirm?", false)
	require.Error(t, err)
}
