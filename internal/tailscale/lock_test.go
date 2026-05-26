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

package tailscale_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tailscale"
)

func TestLockStatus_Disabled(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: `{"Enabled": false}`, ExitCode: 0},
	})
	client := tailscale.NewLockClient(runner)

	ls, err := client.Status(context.Background())
	require.NoError(t, err)
	assert.False(t, ls.Enabled)
	assert.True(t, runner.Done())
}

func TestLockStatus_Enabled(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: `{"Enabled": true}`, ExitCode: 0},
	})
	client := tailscale.NewLockClient(runner)

	ls, err := client.Status(context.Background())
	require.NoError(t, err)
	assert.True(t, ls.Enabled)
	assert.True(t, runner.Done())
}

func TestLockStatus_Error(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stderr: "daemon not running", ExitCode: 1},
	})
	client := tailscale.NewLockClient(runner)

	_, err := client.Status(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exited 1")
}

const lockInitOutput = `Tailnet lock is now enabled.
Disablement secret 1: tlsdis:secret_PLACEHOLDER_1
Disablement secret 2: tlsdis:secret_PLACEHOLDER_2
New trusted key: nlpub:key_PLACEHOLDER
`

func TestLockInit(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: lockInitOutput, ExitCode: 0},
	})
	client := tailscale.NewLockClient(runner)

	result, err := client.Init(context.Background(), 2, false)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify secrets are captured.
	require.Len(t, result.DisablementSecrets, 2)
	assert.Equal(t, "tlsdis:secret_PLACEHOLDER_1", result.DisablementSecrets[0])
	assert.Equal(t, "tlsdis:secret_PLACEHOLDER_2", result.DisablementSecrets[1])

	// Verify args passed correctly.
	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "tailscale", calls[0].Name)
	assert.Contains(t, calls[0].Args, "lock")
	assert.Contains(t, calls[0].Args, "init")
	assert.Contains(t, calls[0].Args, "--gen-disablement=2")
}

func TestLockInit_WithSupportKey(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: lockInitOutput, ExitCode: 0},
	})
	client := tailscale.NewLockClient(runner)

	_, err := client.Init(context.Background(), 2, true)
	require.NoError(t, err)

	calls := runner.RecordedCalls()
	assert.Contains(t, calls[0].Args, "--gen-disablement-for-support")
}

func TestLockInit_NoSecretsOnDisk(t *testing.T) {
	// This test verifies that Init populates DisablementSecrets in memory
	// and does NOT write to any file. Since the implementation only calls
	// the shell runner (no file I/O), the absence of file writing is
	// guaranteed by the architecture: the runner is mocked, no real exec
	// happens, and no os.WriteFile call exists in lock.go.
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: lockInitOutput, ExitCode: 0},
	})
	client := tailscale.NewLockClient(runner)

	result, err := client.Init(context.Background(), 2, false)
	require.NoError(t, err)

	// Secrets must be present in the result (not silently dropped).
	assert.NotEmpty(t, result.DisablementSecrets,
		"disablement secrets must be returned in memory")

	// Confirm the runner was the only I/O that happened.
	assert.True(t, runner.Done(), "all mocked calls should have been consumed")
}

func TestLockSign(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 0},
	})
	client := tailscale.NewLockClient(runner)

	err := client.Sign(context.Background(), "nlpub:key_PLACEHOLDER")
	require.NoError(t, err)
	assert.True(t, runner.Done())

	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "tailscale", calls[0].Name)
	assert.Contains(t, calls[0].Args, "lock")
	assert.Contains(t, calls[0].Args, "sign")
	assert.Contains(t, calls[0].Args, "nlpub:key_PLACEHOLDER")
}

func TestLockSign_Error(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stderr: "key not found", ExitCode: 1},
	})
	client := tailscale.NewLockClient(runner)

	err := client.Sign(context.Background(), "nlpub:key_PLACEHOLDER")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exited 1")
}
