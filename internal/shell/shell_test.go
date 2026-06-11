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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/shell"
)

func TestExecRunner_Success(t *testing.T) {
	r := &shell.ExecRunner{}
	res, err := r.Run(context.Background(), "echo", "hello")
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, "hello\n", res.Stdout)
}

func TestExecRunner_NonZeroExit(t *testing.T) {
	r := &shell.ExecRunner{}
	res, err := r.Run(context.Background(), "sh", "-c", "exit 42")
	require.NoError(t, err, "non-zero exit must not be a Go error")
	assert.Equal(t, 42, res.ExitCode)
}

func TestExecRunner_Stderr(t *testing.T) {
	r := &shell.ExecRunner{}
	res, err := r.Run(context.Background(), "sh", "-c", "echo err >&2; exit 1")
	require.NoError(t, err)
	assert.Equal(t, 1, res.ExitCode)
	assert.Contains(t, res.Stderr, "err")
}

func TestExecRunner_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &shell.ExecRunner{}
	_, err := r.Run(ctx, "sleep", "10")
	require.Error(t, err, "cancelled context must return an error")
}

func TestExecRunner_CommandNotFound(t *testing.T) {
	r := &shell.ExecRunner{}
	_, err := r.Run(context.Background(), "this-binary-does-not-exist-abysslink")
	require.Error(t, err)
}

func TestMockRunner_ScriptedCalls(t *testing.T) {
	m := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "ok", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "two", ExitCode: 0}},
	)
	r1, err := m.Run(context.Background(), "cmd1")
	require.NoError(t, err)
	assert.Equal(t, "ok", r1.Stdout)

	r2, err := m.Run(context.Background(), "cmd2")
	require.NoError(t, err)
	assert.Equal(t, "two", r2.Stdout)

	assert.True(t, m.Done())
}

func TestMockRunner_UnexpectedCall(t *testing.T) {
	m := shell.NewMockRunner()
	_, err := m.Run(context.Background(), "cmd")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "unexpected call"))
}

func TestMockRunner_ScriptedError(t *testing.T) {
	m := shell.NewMockRunner(
		shell.Call{Err: context.DeadlineExceeded},
	)
	_, err := m.Run(context.Background(), "cmd")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestResultOk verifies the Ok() helper: it is the single idiom callers use to
// distinguish a successful exit from a non-zero exit that Run reports with a
// nil error (the ignored-ExitCode bug class).
func TestResultOk(t *testing.T) {
	assert.True(t, shell.Result{ExitCode: 0}.Ok(), "exit 0 is Ok")
	assert.False(t, shell.Result{ExitCode: 1}.Ok(), "exit 1 is not Ok")
	assert.False(t, shell.Result{ExitCode: 255}.Ok(), "exit 255 is not Ok")
}
