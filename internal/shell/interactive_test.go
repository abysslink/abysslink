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

package shell_test

import (
	"context"
	"errors"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecRunner_RunInteractive(t *testing.T) {
	r := &shell.ExecRunner{}
	// `true` exits 0; `false` exits non-zero.
	require.NoError(t, r.RunInteractive(context.Background(), "true"))
	assert.Error(t, r.RunInteractive(context.Background(), "false"))
}

func TestMockRunner_RunInteractive(t *testing.T) {
	wantErr := errors.New("login cancelled")
	m := shell.NewMockRunner(
		shell.Call{},             // first call: success
		shell.Call{Err: wantErr}, // second call: error
	)

	require.NoError(t, m.RunInteractive(context.Background(), "tailscale", "up", "--ssh"))
	err := m.RunInteractive(context.Background(), "tailscale", "up")
	assert.ErrorIs(t, err, wantErr)

	calls := m.RecordedCalls()
	require.Len(t, calls, 2)
	assert.Equal(t, "tailscale", calls[0].Name)
	assert.Equal(t, []string{"up", "--ssh"}, calls[0].Args)
}
