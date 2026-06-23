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

package deadman

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// readSourceFile reads a package source file for static assertions.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // test-controlled in-package filename
	require.NoError(t, err)
	return string(b)
}

// recordingAppender captures audit Append calls for assertions.
type recordingAppender struct {
	mu      sync.Mutex
	entries []string // "op|target"
}

func (a *recordingAppender) Append(op, target string, _ []byte, _ bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, op+"|"+target)
	return nil
}

func (a *recordingAppender) ops() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.entries))
	copy(out, a.entries)
	return out
}

// sigCall records one signal sent during lockdown.
type sigCall struct {
	pgid int
	sig  syscall.Signal
}

// newSigRecorder returns a SignalFunc that records every call, plus an accessor.
func newSigRecorder() (SignalFunc, func() []sigCall) {
	var mu sync.Mutex
	var calls []sigCall
	fn := func(pgid int, sig syscall.Signal) error {
		mu.Lock()
		calls = append(calls, sigCall{pgid, sig})
		mu.Unlock()
		return nil
	}
	get := func() []sigCall {
		mu.Lock()
		defer mu.Unlock()
		out := make([]sigCall, len(calls))
		copy(out, calls)
		return out
	}
	return fn, get
}

func TestLockdownDisarmsArmedPgids(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	require.NoError(t, reg.Register(ArmedRun{PGID: 111, ClosureHash: "a", ArmedAt: time.Now().UTC()}))
	require.NoError(t, reg.Register(ArmedRun{PGID: 222, ClosureHash: "b", ArmedAt: time.Now().UTC()}))

	sigFn, getCalls := newSigRecorder()
	aud := &recordingAppender{}
	revoked := 0

	opts := LockdownOpts{
		Registry:       reg,
		SignalFn:       sigFn,
		RevokeAutonomy: func() error { revoked++; return nil },
		Audit:          aud,
		Reason:         "no-contact-timeout",
		KillGrace:      time.Millisecond, // keep the test fast
	}
	require.NoError(t, Lockdown(context.Background(), opts))

	calls := getCalls()
	// Every registered pgid must receive SIGTERM then SIGKILL.
	for _, pgid := range []int{111, 222} {
		var gotTerm, gotKill bool
		for _, c := range calls {
			if c.pgid == pgid && c.sig == syscall.SIGTERM {
				gotTerm = true
			}
			if c.pgid == pgid && c.sig == syscall.SIGKILL {
				gotKill = true
			}
		}
		require.True(t, gotTerm, "pgid %d should receive SIGTERM", pgid)
		require.True(t, gotKill, "pgid %d should receive SIGKILL", pgid)
	}

	// Autonomy revoked exactly once; audit recorded a deadman-lockdown entry.
	require.Equal(t, 1, revoked, "autonomy-revoke hook must be invoked exactly once")
	var sawLockdownEntry bool
	for _, op := range aud.ops() {
		if strings.HasPrefix(op, "deadman-lockdown|") {
			sawLockdownEntry = true
		}
	}
	require.True(t, sawLockdownEntry, "audit must record a deadman-lockdown entry")

	// Disarmed pgids are deregistered from the registry.
	runs, err := reg.List()
	require.NoError(t, err)
	require.Empty(t, runs, "disarmed pgids must be removed from the registry")
}

func TestLockdownOneFailureDoesNotStrandOthers(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	require.NoError(t, reg.Register(ArmedRun{PGID: 111, ClosureHash: "a", ArmedAt: time.Now().UTC()}))
	require.NoError(t, reg.Register(ArmedRun{PGID: 222, ClosureHash: "b", ArmedAt: time.Now().UTC()}))

	var mu sync.Mutex
	var killed222 bool
	sigFn := func(pgid int, sig syscall.Signal) error {
		mu.Lock()
		defer mu.Unlock()
		if pgid == 111 {
			return errors.New("simulated signal failure on 111")
		}
		if pgid == 222 && sig == syscall.SIGKILL {
			killed222 = true
		}
		return nil
	}

	opts := LockdownOpts{
		Registry:  reg,
		SignalFn:  sigFn,
		Audit:     &recordingAppender{},
		Reason:    "test",
		KillGrace: time.Millisecond,
	}
	err := Lockdown(context.Background(), opts)
	require.Error(t, err, "an aggregate error is returned when a pgid fails")

	mu.Lock()
	defer mu.Unlock()
	require.True(t, killed222, "a failure on 111 must not prevent disarming 222")
}

func TestLockdownEmptyRegistryNoPanicNoError(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	sigFn, getCalls := newSigRecorder()
	opts := LockdownOpts{
		Registry: reg,
		SignalFn: sigFn,
		Audit:    &recordingAppender{},
		Reason:   "empty",
	}
	require.NoError(t, Lockdown(context.Background(), opts))
	require.Empty(t, getCalls(), "no pgids to disarm => no signals")
}

func TestLockdownNilRegistryNoPanic(t *testing.T) {
	opts := LockdownOpts{
		Registry: nil,
		Audit:    &recordingAppender{},
		Reason:   "nil",
	}
	require.NoError(t, Lockdown(context.Background(), opts))
}

func TestLockdownSkipsNonPositivePgid(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	// A corrupt/forged entry with a non-positive pgid must never be signalled
	// (T-32-23: syscall.Kill(-pgid) on a bad pgid signals the wrong group).
	require.NoError(t, reg.Register(ArmedRun{PGID: 0, ClosureHash: "bad", ArmedAt: time.Now().UTC()}))
	require.NoError(t, reg.Register(ArmedRun{PGID: 333, ClosureHash: "ok", ArmedAt: time.Now().UTC()}))

	sigFn, getCalls := newSigRecorder()
	opts := LockdownOpts{
		Registry:  reg,
		SignalFn:  sigFn,
		Audit:     &recordingAppender{},
		Reason:    "skip-bad",
		KillGrace: time.Millisecond,
	}
	require.NoError(t, Lockdown(context.Background(), opts))
	for _, c := range getCalls() {
		require.NotEqual(t, 0, c.pgid, "non-positive pgid must never be signalled")
	}
}

// TestLockdownDoesNotTouchSSHCAOrDeviceOrNetwork is a static source assertion
// (T-32-21): the lockdown implementation must not import or reference any
// SSH-CA / device-credential / network-revocation package or symbol. Lockdown
// is scoped to disarm + revoke-autonomy + audit ONLY.
func TestLockdownDoesNotTouchSSHCAOrDeviceOrNetwork(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lockdown.go", nil, parser.ParseComments)
	require.NoError(t, err)

	forbidden := []string{
		"internal/ssh",    // SSH CA revocation
		"internal/ca",     // CA
		"internal/device", // device credentials
		"internal/tailscale",
		"internal/backend",
		"internal/headscale",
		"internal/netbird",
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range forbidden {
			require.NotContains(t, path, bad,
				"lockdown.go must NOT import %s — disarm+revoke+audit only (T-32-21)", bad)
		}
	}

	// Also assert no obvious revocation-symbol references appear in the source.
	src := readSourceFile(t, "lockdown.go")
	for _, sym := range []string{"RevokeCA", "RevokeDevice", "RevokeNetwork", "TailnetLock", "kill-pane"} {
		require.NotContains(t, src, sym,
			"lockdown.go must not reference %s (over-reach beyond disarm scope)", sym)
	}
}
