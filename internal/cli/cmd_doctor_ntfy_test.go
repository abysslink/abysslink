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
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNtfyBindCheck verifies the primary D-02 check: docker inspect HostIp
// classification. Each sub-test scripts a MockRunner to return a specific
// HostIp string and asserts the expected Severity and Check name.
func TestNtfyBindCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name        string
		stdout      string // docker inspect formatted output
		exitCode    int
		runErr      error
		wantSev     modules.Severity
		wantCheckID string
	}{
		{
			name:        "FATAL_loopback",
			stdout:      "127.0.0.1 ",
			wantSev:     modules.SeverityFatal,
			wantCheckID: "ntfy-bind",
		},
		{
			name:        "FATAL_wildcard_ipv4",
			stdout:      "0.0.0.0 ",
			wantSev:     modules.SeverityFatal,
			wantCheckID: "ntfy-bind",
		},
		{
			name:        "FATAL_wildcard_ipv6",
			stdout:      ":: ",
			wantSev:     modules.SeverityFatal,
			wantCheckID: "ntfy-bind",
		},
		{
			name:        "FATAL_localhost_string",
			stdout:      "localhost ",
			wantSev:     modules.SeverityFatal,
			wantCheckID: "ntfy-bind",
		},
		{
			name:        "OK_tailnet",
			stdout:      "100.64.0.1 ",
			wantSev:     modules.SeverityOK,
			wantCheckID: "ntfy-bind",
		},
		{
			name:        "FATAL_inspect_error",
			runErr:      fmt.Errorf("docker: daemon not running"),
			wantSev:     modules.SeverityFatal,
			wantCheckID: "ntfy-bind",
		},
		{
			name:        "FATAL_nonzero_exit",
			exitCode:    1,
			stdout:      "",
			wantSev:     modules.SeverityFatal,
			wantCheckID: "ntfy-bind",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mr := shell.NewMockRunner(shell.Call{
				Result: shell.Result{Stdout: tc.stdout, ExitCode: tc.exitCode},
				Err:    tc.runErr,
			})
			f := ntfyBindCheck(ctx, mr, ntfyDockerContainerName)
			assert.Equal(t, tc.wantSev, f.Severity, "severity mismatch")
			assert.Equal(t, tc.wantCheckID, f.Check, "check ID mismatch")
			assert.Equal(t, "ntfy", f.Module, "module must be 'ntfy' not 'webui'")
		})
	}
}

// TestNtfyContainerPresent verifies that ntfyContainerPresent returns true only
// when docker inspect exits 0, and false on non-zero exit or runner error.
func TestNtfyContainerPresent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("present_exit0", func(t *testing.T) {
		t.Parallel()
		mr := shell.NewMockRunner(shell.Call{
			Result: shell.Result{ExitCode: 0, Stdout: "[{...}]"},
		})
		assert.True(t, ntfyContainerPresent(ctx, mr, ntfyDockerContainerName))
	})

	t.Run("absent_nonzero_exit", func(t *testing.T) {
		t.Parallel()
		mr := shell.NewMockRunner(shell.Call{
			Result: shell.Result{ExitCode: 1, Stderr: "Error: No such container: abysslink-ntfy"},
		})
		assert.False(t, ntfyContainerPresent(ctx, mr, ntfyDockerContainerName))
	})

	t.Run("absent_runner_error", func(t *testing.T) {
		t.Parallel()
		mr := shell.NewMockRunner(shell.Call{
			Err: fmt.Errorf("docker: daemon not running"),
		})
		assert.False(t, ntfyContainerPresent(ctx, mr, ntfyDockerContainerName))
	})
}

// TestNtfyBindFindings verifies the container-presence gate introduced by CR-01:
// on a native (no-container) Linux install the docker-inspect FATAL is NOT
// emitted; on a Docker install the full ntfyBindCheck + loopback checks run.
func TestNtfyBindFindings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Helper: grab a guaranteed-free port by binding then immediately closing.
	freePort := func(t *testing.T) int {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		return port
	}

	t.Run("native_no_container_no_FATAL", func(t *testing.T) {
		t.Parallel()
		// ntfyContainerPresent → exit 1 (no container).
		// ntfyLoopbackReachCheck dials a free (closed) port → SeverityOK.
		mr := shell.NewMockRunner(shell.Call{
			Result: shell.Result{ExitCode: 1, Stderr: "Error: No such container"},
		})
		port := freePort(t)
		cfg := &config.Config{}
		cfg.Modules.Ntfy.Enabled = true
		cfg.Modules.Ntfy.Port = port

		finds := ntfyBindFindings(ctx, mr, cfg)
		require.Len(t, finds, 1, "native mode: only loopback check expected")
		assert.Equal(t, "ntfy-loopback", finds[0].Check)
		assert.Equal(t, modules.SeverityOK, finds[0].Severity,
			"native install with no loopback listener must not FATAL")
	})

	t.Run("docker_present_bad_hostip_FATAL", func(t *testing.T) {
		t.Parallel()
		// Call 1: ntfyContainerPresent → exit 0 (container exists).
		// Call 2: ntfyBindCheck inspect → exit 0, HostIp=127.0.0.1 → FATAL.
		mr := shell.NewMockRunner(
			shell.Call{Result: shell.Result{ExitCode: 0}},
			shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "127.0.0.1 "}},
		)
		port := freePort(t)
		cfg := &config.Config{}
		cfg.Modules.Ntfy.Enabled = true
		cfg.Modules.Ntfy.Port = port

		finds := ntfyBindFindings(ctx, mr, cfg)
		require.GreaterOrEqual(t, len(finds), 1)
		assert.Equal(t, "ntfy-bind", finds[0].Check)
		assert.Equal(t, modules.SeverityFatal, finds[0].Severity,
			"container present + loopback HostIp must FATAL")
	})

	t.Run("docker_present_inspect_error_FATAL", func(t *testing.T) {
		t.Parallel()
		// Call 1: ntfyContainerPresent → exit 0 (container exists).
		// Call 2: ntfyBindCheck inspect → runner error → FATAL (T-22-10).
		mr := shell.NewMockRunner(
			shell.Call{Result: shell.Result{ExitCode: 0}},
			shell.Call{Err: fmt.Errorf("docker: connection refused")},
		)
		port := freePort(t)
		cfg := &config.Config{}
		cfg.Modules.Ntfy.Enabled = true
		cfg.Modules.Ntfy.Port = port

		finds := ntfyBindFindings(ctx, mr, cfg)
		require.GreaterOrEqual(t, len(finds), 1)
		assert.Equal(t, "ntfy-bind", finds[0].Check)
		assert.Equal(t, modules.SeverityFatal, finds[0].Severity,
			"container present but uninspectable must FATAL (T-22-10)")
	})

	t.Run("disabled_no_findings", func(t *testing.T) {
		t.Parallel()
		mr := shell.NewMockRunner() // no calls expected
		cfg := &config.Config{}
		cfg.Modules.Ntfy.Enabled = false

		finds := ntfyBindFindings(ctx, mr, cfg)
		assert.Empty(t, finds, "disabled ntfy must emit no findings")
	})
}

// TestNtfyLoopbackReachCheck verifies the secondary D-02 check: TCP dial to
// 127.0.0.1:<port>. The FATAL case starts a real TCP listener on a free port
// so the dial succeeds; the OK case uses a port with no listener.
func TestNtfyLoopbackReachCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("FATAL_loopback_answers", func(t *testing.T) {
		t.Parallel()
		// Start a TCP listener on an OS-assigned free port.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()
		// Accept connections in background to avoid ECONNREFUSED after accept queue fills.
		go func() {
			for {
				c, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				_ = c.Close()
			}
		}()

		port := ln.Addr().(*net.TCPAddr).Port
		cfg := &config.Config{}
		cfg.Modules.Ntfy.Enabled = true
		cfg.Modules.Ntfy.Port = port

		f := ntfyLoopbackReachCheck(ctx, cfg)
		assert.Equal(t, modules.SeverityFatal, f.Severity)
		assert.Equal(t, "ntfy-loopback", f.Check)
		assert.Equal(t, "ntfy", f.Module)
	})

	t.Run("OK_no_listener", func(t *testing.T) {
		t.Parallel()
		// Bind and immediately close a listener to get a guaranteed-free port.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		cfg := &config.Config{}
		cfg.Modules.Ntfy.Enabled = true
		cfg.Modules.Ntfy.Port = port

		f := ntfyLoopbackReachCheck(ctx, cfg)
		assert.Equal(t, modules.SeverityOK, f.Severity)
		assert.Equal(t, "ntfy-loopback", f.Check)
		assert.Equal(t, "ntfy", f.Module)
	})

	t.Run("OK_ntfy_disabled", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{}
		cfg.Modules.Ntfy.Enabled = false

		f := ntfyLoopbackReachCheck(ctx, cfg)
		assert.Equal(t, modules.SeverityOK, f.Severity)
		assert.Equal(t, "ntfy-loopback", f.Check)
		assert.Equal(t, "ntfy", f.Module)
	})
}
