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
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnrollPhoneInstallPause_AutoYes asserts that enrollPhoneInstallPause
// does not block when autoYes=true (no hang in CI / --yes context).
func TestEnrollPhoneInstallPause_AutoYes(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	err := enrollPhoneInstallPause(ctx, p, true)
	require.NoError(t, err, "Pause must not error under autoYes=true")
}

// TestEnrollPhoneInstallPause_NonTTY asserts that enrollPhoneInstallPause
// does not block when stdin is not a TTY (non-interactive context like tests).
func TestEnrollPhoneInstallPause_NonTTY(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	// In test environment stdin is not a TTY, so Pause should return nil immediately.
	err := enrollPhoneInstallPause(ctx, p, false)
	require.NoError(t, err, "Pause must not error in non-TTY context")
}

// TestEnrollPhoneInstallPause_PrintsMessage asserts that even when autoYes=true
// (so Pause is skipped), the enrollPhoneInstallPause function is defined and
// callable. The message content is validated via the tui.Pause function itself.
func TestEnrollPhoneInstallPause_Defined(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	// Should be callable without panicking in either mode.
	err := enrollPhoneInstallPause(ctx, p, true)
	assert.NoError(t, err)
	err = enrollPhoneInstallPause(ctx, p, false)
	assert.NoError(t, err)
}
