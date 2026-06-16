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

package approve

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCAS_FirstAnswerWins: open a pendingReq; call resolve(stateApproved) in
// goroutine 1 and resolve(stateDenied) in goroutine 2 concurrently; exactly
// one returns true, the other false. Run with -race.
func TestCAS_FirstAnswerWins(t *testing.T) {
	t.Parallel()
	reg := NewRegistry(nil)

	var hash [32]byte
	req, err := reg.Open("req-cas", hash, TierSensitive, "sig")
	require.NoError(t, err)

	// Barrier so both goroutines race as closely as possible.
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})

	var trueCount atomic.Int32
	go func() {
		defer wg.Done()
		<-start
		if req.resolve(stateApproved) {
			trueCount.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		if req.resolve(stateDenied) {
			trueCount.Add(1)
		}
	}()

	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), trueCount.Load(), "exactly one resolve must return true")
}

// TestResolution_TimeoutDeny: Registry.Wait(ctx) with a context that expires
// immediately returns (Resolution{Approved:false}, ErrTimeout) when hasTTY=true.
func TestResolution_TimeoutDeny(t *testing.T) {
	t.Parallel()
	reg := NewRegistry(nil)

	var hash [32]byte
	req, err := reg.Open("req-timeout", hash, TierSensitive, "sig")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure ctx is expired

	res, waitErr := reg.Wait(ctx, req, true /* hasTTY */)
	assert.ErrorIs(t, waitErr, ErrTimeout, "expected ErrTimeout on context expiry with TTY")
	assert.False(t, res.Approved, "must not return Approved:true on timeout")
}

// TestResolution_HeadlessDeny: When hasTTY=false and context fires, result is
// deny (not TTY fallback). Verify no code path returns Approved:true.
func TestResolution_HeadlessDeny(t *testing.T) {
	t.Parallel()
	reg := NewRegistry(nil)

	var hash [32]byte
	req, err := reg.Open("req-headless", hash, TierSensitive, "sig")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure ctx is expired

	res, waitErr := reg.Wait(ctx, req, false /* hasTTY */)
	assert.ErrorIs(t, waitErr, ErrDenied, "headless timeout must return ErrDenied")
	assert.False(t, res.Approved, "headless timeout must never return Approved:true")
}

// TestConcurrentRequests: Open 10 requests concurrently; resolve each
// independently; all 10 channels drain without deadlock or data race (-race).
func TestConcurrentRequests(t *testing.T) {
	t.Parallel()
	const n = 10
	reg := NewRegistry(nil)

	var (
		wg   sync.WaitGroup
		reqs [n]*pendingReq
		mu   sync.Mutex
	)

	// Open all requests concurrently.
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			var hash [32]byte
			hash[0] = byte(i)
			req, err := reg.Open(strings.Repeat("x", 8)+string(rune('0'+i)), hash, TierSensitive, "sig")
			if err != nil {
				t.Errorf("Open failed: %v", err)
				return
			}
			mu.Lock()
			reqs[i] = req
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Resolve each independently and drain.
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			mu.Lock()
			req := reqs[i]
			mu.Unlock()
			if req == nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ok := reg.Resolve(req.requestID, stateApproved)
			assert.True(t, ok, "first resolve must return true")
			res, err := reg.Wait(ctx, req, true)
			assert.NoError(t, err)
			assert.True(t, res.Approved)
		}(i)
	}
	wg.Wait()
}

// TestTier_CriticalRefused: Registry.Open() with actionName="panic-revoke" and
// declaredTier=TierSensitive returns ErrCriticalTierTTYOnly; nothing is added
// to the pending map.
func TestTier_CriticalRefused(t *testing.T) {
	t.Parallel()
	reg := NewRegistry(nil)

	var hash [32]byte
	_, err := reg.Open("req-critical", hash, TierSensitive, "sig", WithActionName("panic-revoke"))
	require.ErrorIs(t, err, ErrCriticalTierTTYOnly, "panic-revoke must be refused")

	// The map must be empty.
	reg.mu.Lock()
	pendingLen := len(reg.pending)
	reg.mu.Unlock()
	assert.Equal(t, 0, pendingLen, "no pending entry must be added for critical tier")
}

// TestResolve_LateApproveRejected: resolve(stateDenied) then
// resolve(stateApproved) — second call returns false; ch receives exactly one
// Resolution{Approved:false}.
func TestResolve_LateApproveRejected(t *testing.T) {
	t.Parallel()
	reg := NewRegistry(nil)

	var hash [32]byte
	req, err := reg.Open("req-late", hash, TierSensitive, "sig")
	require.NoError(t, err)

	// First resolution: deny.
	first := req.resolve(stateDenied)
	assert.True(t, first, "first resolution must return true")

	// Late approval must be rejected.
	second := req.resolve(stateApproved)
	assert.False(t, second, "late approval must return false (first answer won)")

	// Channel must have exactly one Resolution{Approved:false}.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res, waitErr := reg.Wait(ctx, req, true)
	assert.ErrorIs(t, waitErr, ErrDenied, "deny resolution must return ErrDenied")
	assert.False(t, res.Approved, "must see the first (deny) resolution")

	// Channel must be drained and not block.
	select {
	case extra := <-req.ch:
		t.Errorf("unexpected second resolution in channel: %+v", extra)
	default:
		// correct: channel is empty
	}
}

// TestApprove_NoClaude enforces that no non-test source file in internal/approve
// imports claudecode or os/exec — zero Claude coupling at the source level.
func TestApprove_NoClaude(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, perr)
		for _, imp := range f.Imports {
			path := imp.Path.Value
			assert.NotEqual(t, `"os/exec"`, path,
				"%s must not import os/exec (use shell.ResolvePath)", name)
			assert.NotContains(t, path, "claudecode",
				"%s must not import claudecode (zero Claude coupling)", name)
			assert.NotContains(t, path, "modules/claude",
				"%s must not import claude modules", name)
		}
		checked++
	}
	assert.Positive(t, checked, "expected at least one non-test source file to check")
}
