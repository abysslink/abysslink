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
	"context"
	"runtime"
	"strings"
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

// TestBuildMinimalEnv_Allowlist verifies B10: env minimization is an ALLOWLIST.
// PATH/HOME and the keyless-flow vars pass through; a non-allowlisted (secret-
// looking) parent var does NOT. A newly-introduced unknown var also does not
// pass — proving this is an allowlist, not a denylist.
func TestBuildMinimalEnv_Allowlist(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/u",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
		"GIT_TERMINAL_PROMPT=0",
		"TMPDIR=/tmp",
		"SIGSTORE_REKOR_URL=https://rekor.example",
		"XDG_CONFIG_HOME=/home/u/.config",
		"AWS_SECRET_ACCESS_KEY=super-secret", // must be filtered
		"SOME_FUTURE_UNKNOWN_VAR=leak-me",    // must be filtered (allowlist proof)
		"NTFY_TOPIC_CREDENTIAL=topic-secret", // must be filtered
	}
	got := buildMinimalEnv(parent)
	gotKeys := map[string]string{}
	for _, e := range got {
		k, v, _ := strings.Cut(e, "=")
		gotKeys[k] = v
	}

	// Keyless-flow + base vars present.
	for _, k := range []string{"PATH", "HOME", "SSH_AUTH_SOCK", "GIT_TERMINAL_PROMPT", "TMPDIR", "SIGSTORE_REKOR_URL", "XDG_CONFIG_HOME"} {
		_, ok := gotKeys[k]
		assert.Truef(t, ok, "allowlisted var %s must pass through minimization", k)
	}
	// Secret-looking and unknown vars absent.
	for _, k := range []string{"AWS_SECRET_ACCESS_KEY", "SOME_FUTURE_UNKNOWN_VAR", "NTFY_TOPIC_CREDENTIAL"} {
		_, ok := gotKeys[k]
		assert.Falsef(t, ok, "non-allowlisted var %s must NOT pass through (allowlist, not denylist)", k)
	}
}

// TestRunMinimal_EnvAllowlist verifies B10 end-to-end: a child process spawned
// through RunMinimal sees only the allowlisted environment. It spawns a Go test
// helper (no sh -c) that prints its own environment, then asserts the secret var
// is absent while PATH/HOME are present.
func TestRunMinimal_EnvAllowlist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("env helper assumes POSIX")
	}

	secret := "ABYSSLINK_SECRET_PROBE"
	t.Setenv(secret, "leak-me")
	t.Setenv("HOME", "/home/probe")

	r := &ExecRunner{}
	// `env` with no args prints the child environment, one VAR=VAL per line.
	res, err := r.RunMinimal(context.Background(), "env")
	require.NoError(t, err)
	require.Equal(t, 0, res.ExitCode, "env should exit 0; stderr=%s", res.Stderr)

	assert.NotContains(t, res.Stdout, secret+"=", "secret var must be absent from minimized child env")
	assert.Contains(t, res.Stdout, "PATH=", "PATH must be present in minimized child env")
	assert.Contains(t, res.Stdout, "HOME=/home/probe", "HOME must be present in minimized child env")
}
