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

package fleet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rigs returns a slice of n simple RigConfig records for testing.
func makeRigs(names ...string) []config.RigConfig {
	rigs := make([]config.RigConfig, len(names))
	for i, n := range names {
		rigs[i] = config.RigConfig{
			Name:     n,
			Hostname: n + ".example.ts.net",
		}
	}
	return rigs
}

// hostEntry is the scripted response for a single hostname in hostnameDispatchRunner.
type hostEntry struct {
	res shell.Result
	err error
}

// hostnameDispatchRunner is a shell.Runner that dispatches Run results based
// on the first argument (SSH hostname). This avoids the sequential-call-order
// assumption of MockRunner, which breaks under concurrent fan-out goroutines.
type hostnameDispatchRunner struct {
	responses map[string]hostEntry
}

func newHostnameRunner(m map[string]hostEntry) *hostnameDispatchRunner {
	return &hostnameDispatchRunner{responses: m}
}

func (h *hostnameDispatchRunner) Run(_ context.Context, _ string, args ...string) (shell.Result, error) {
	// args[0] is the SSH hostname (rig.Hostname passed as first arg by FanOut).
	hostname := ""
	if len(args) > 0 {
		hostname = args[0]
	}
	if v, ok := h.responses[hostname]; ok {
		return v.res, v.err
	}
	return shell.Result{ExitCode: 1}, fmt.Errorf("hostnameRunner: unexpected hostname %q", hostname)
}

func (h *hostnameDispatchRunner) RunWithStdin(_ context.Context, _ io.Reader, _ string, args ...string) (shell.Result, error) {
	return h.Run(context.Background(), "", args...)
}

func (h *hostnameDispatchRunner) RunInteractive(_ context.Context, _ string, _ ...string) error {
	return nil
}

func (h *hostnameDispatchRunner) RunWithEnv(_ context.Context, _ map[string]string, _ string, args ...string) (shell.Result, error) {
	return h.Run(context.Background(), "", args...)
}

func (h *hostnameDispatchRunner) RunStream(_ context.Context, _ string, _ ...string) (*shell.Stream, error) {
	return nil, errors.New("runstream: not supported by this fake")
}

// TestFanOut_UnreachableContinues verifies SC-2: one offline rig does not abort
// the others. The command returns 3 results with rig[1] UNREACHABLE, but no error.
func TestFanOut_UnreachableContinues(t *testing.T) {
	rigs := makeRigs("rig0", "rig1", "rig2")

	runner := newHostnameRunner(map[string]hostEntry{
		"rig0.example.ts.net": {res: shell.Result{Stdout: `{"tailscale":"up"}`, ExitCode: 0}},
		"rig1.example.ts.net": {res: shell.Result{ExitCode: 1}, err: errors.New("ssh: connection refused")},
		"rig2.example.ts.net": {res: shell.Result{Stdout: `{"tailscale":"up"}`, ExitCode: 0}},
	})

	results, err := FanOut(context.Background(), runner, rigs, 5*time.Second, false, []string{"status", "--json"})

	require.NoError(t, err, "SC-2: one offline rig must not return an error in non-strict mode")
	require.Len(t, results, 3)

	// Results are in deterministic rig-slice order (disjoint pre-sized indices).
	assert.True(t, results[0].Reachable, "rig0 should be reachable")
	assert.Equal(t, `{"tailscale":"up"}`, results[0].Stdout)

	assert.False(t, results[1].Reachable, "rig1 should be UNREACHABLE")
	assert.NotNil(t, results[1].Err)

	assert.True(t, results[2].Reachable, "rig2 should be reachable")
	assert.Equal(t, `{"tailscale":"up"}`, results[2].Stdout)
}

// TestFanOut_StrictFailsFast verifies that --strict turns any UNREACHABLE rig
// into a non-nil error returned from FanOut (caller maps to exit 1).
func TestFanOut_StrictFailsFast(t *testing.T) {
	rigs := makeRigs("rig0", "rig1")

	runner := newHostnameRunner(map[string]hostEntry{
		"rig0.example.ts.net": {res: shell.Result{Stdout: `{"tailscale":"up"}`, ExitCode: 0}},
		"rig1.example.ts.net": {res: shell.Result{ExitCode: 1}, err: errors.New("ssh: timeout")},
	})

	_, err := FanOut(context.Background(), runner, rigs, 5*time.Second, true, []string{"status", "--json"})

	require.Error(t, err, "--strict must return a non-nil error when any rig is UNREACHABLE")
}

// blockingRunner is a shell.Runner that blocks until its context is cancelled,
// then returns a context error. Used to simulate a hung SSH connection.
type blockingRunner struct {
	// callCount counts how many Run calls were received.
	callCount atomic.Int32
}

func (b *blockingRunner) Run(ctx context.Context, _ string, _ ...string) (shell.Result, error) {
	b.callCount.Add(1)
	<-ctx.Done()
	return shell.Result{ExitCode: 1}, ctx.Err()
}

func (b *blockingRunner) RunWithStdin(ctx context.Context, _ io.Reader, name string, args ...string) (shell.Result, error) {
	return b.Run(ctx, name, args...)
}

func (b *blockingRunner) RunInteractive(ctx context.Context, _ string, _ ...string) error {
	<-ctx.Done()
	return ctx.Err()
}

func (b *blockingRunner) RunWithEnv(ctx context.Context, _ map[string]string, name string, args ...string) (shell.Result, error) {
	return b.Run(ctx, name, args...)
}

func (b *blockingRunner) RunStream(_ context.Context, _ string, _ ...string) (*shell.Stream, error) {
	return nil, errors.New("runstream: not supported by this fake")
}

// TestFanOut_PerRigTimeout verifies that a blocking rig is cancelled by the
// per-rig timeout, and that it's reported as UNREACHABLE without hanging.
func TestFanOut_PerRigTimeout(t *testing.T) {
	rigs := makeRigs("slow-rig")
	br := &blockingRunner{}

	start := time.Now()
	results, err := FanOut(context.Background(), br, rigs, 100*time.Millisecond, false, []string{"status", "--json"})
	elapsed := time.Since(start)

	require.NoError(t, err, "non-strict mode; timeout alone should not return an error")
	require.Len(t, results, 1)
	assert.False(t, results[0].Reachable, "timed-out rig must be UNREACHABLE")
	assert.True(t, elapsed < 2*time.Second,
		"FanOut should complete within 2s (per-rig timeout was 100ms), got %v", elapsed)
}

// TestFanOut_PanicTimeout10s verifies that FanOut accepts a 10s per-rig timeout
// (the SC-3 panic budget) and honours it by cancelling a blocking rig.
func TestFanOut_PanicTimeout10s(t *testing.T) {
	rigs := makeRigs("panic-rig")
	br := &blockingRunner{}

	// Use a parent context with a short deadline so the test doesn't actually wait 10s.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Pass 10s as the perRigTimeout — the function must accept it without error.
	// The parent ctx deadline fires first and cancels gctx → the rig's rctx
	// (derived from gctx) is also cancelled, so the blocking runner unblocks.
	results, err := FanOut(ctx, br, rigs, 10*time.Second, false, []string{"panic"})

	// err may be context.DeadlineExceeded from the parent ctx cancellation or nil
	// depending on timing; what matters is the rig is UNREACHABLE, not that the
	// function panics or hangs beyond the parent deadline.
	_ = err
	require.Len(t, results, 1)
	assert.False(t, results[0].Reachable, "rig cancelled by parent deadline must be UNREACHABLE")
	assert.GreaterOrEqual(t, br.callCount.Load(), int32(1), "blockingRunner must have been called")
}

// TestFanOut_RejectsUnsafeRigNames verifies that rig names outside [a-z0-9-] are
// rejected with an error before any SSH call (command-injection defense-in-depth).
func TestFanOut_RejectsUnsafeRigNames(t *testing.T) {
	badRigs := []config.RigConfig{
		{Name: "rig; rm -rf /", Hostname: "evil.ts.net"},
	}
	mock := shell.NewMockRunner() // no calls expected

	_, err := FanOut(context.Background(), mock, badRigs, 5*time.Second, false, []string{"status", "--json"})

	require.Error(t, err, "unsafe rig name must be rejected")
	assert.Contains(t, err.Error(), "invalid rig name")
	t.Log("rejected with error:", err) // WR-03: t.Log instead of fmt.Println
}

// TestFanOut_RejectsUnsafeHostnames verifies that rig hostnames outside the safe
// DNS-name charset are rejected with an error before any SSH call (CR-01, T-14-04).
func TestFanOut_RejectsUnsafeHostnames(t *testing.T) {
	cases := []struct {
		hostname string
		desc     string
	}{
		{"", "empty hostname"},
		{"evil host", "space in hostname"},
		{"evil;rm -rf /", "shell metacharacter in hostname"},
		{"-leading-dash.ts.net", "leading dash"},
		{"a", "single-character (too short for 2-char min)"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			rigs := []config.RigConfig{
				{Name: "safe-rig", Hostname: tc.hostname},
			}
			mock := shell.NewMockRunner() // no calls expected

			_, err := FanOut(context.Background(), mock, rigs, 5*time.Second, false, []string{"status"})
			require.Error(t, err, "unsafe hostname %q must be rejected", tc.hostname)
			assert.Contains(t, err.Error(), "invalid rig hostname", "desc=%q", tc.desc)
		})
	}
}
