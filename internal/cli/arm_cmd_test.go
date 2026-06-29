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
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/budget"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubNotifySend installs a no-op notifySendMessage seam for the duration of t
// and restores the original on cleanup. This prevents arm tests from needing a
// live notify daemon while still exercising all paths that call the seam.
func stubNotifySend(t *testing.T) {
	t.Helper()
	orig := notifySendMessage
	notifySendMessage = func(_ context.Context, _ *notifymod.Module, _ notifyv2.Message) error {
		return nil
	}
	t.Cleanup(func() { notifySendMessage = orig })
}

// armTestCC builds a minimal cmdContext for arm tests backed by the given
// MockRunner. A real *audit.Audit is written to t.TempDir() so tests that need
// to inspect audit output can do so; for tests that don't care it is still a
// valid armAuditWriter.
func armTestCC(t *testing.T, mr *shell.MockRunner) (*cmdContext, armAuditWriter, Printer, *bytes.Buffer) {
	t.Helper()
	cfg := config.Defaults()
	cc := &cmdContext{cfg: cfg, runner: mr}
	dir := t.TempDir()
	aud := audit.New(filepath.Join(dir, "audit.log"))
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)
	return cc, aud, p, &buf
}

// makeArmedHandle returns an ArmedHandle where Done is pre-closed (process
// already exited) and PGID is set to a fake positive value for test assertions.
func makeArmedHandle(pgid int) *shell.ArmedHandle {
	done := make(chan struct{})
	close(done) // pre-closed so runArm.Wait doesn't block
	return &shell.ArmedHandle{
		PGID: pgid,
		Done: done,
		Wait: func() error { return nil },
	}
}

// TestArm_StashCreate verifies that runArm calls git rev-parse HEAD and
// git stash create in that order before spawning the process (KILL-04, D-08).
func TestArm_StashCreate(t *testing.T) {
	const fakeHead = "abc123def456"
	const fakeStash = "stash-sha-789"

	mr := shell.NewMockRunner(
		// git rev-parse HEAD
		shell.Call{Result: shell.Result{Stdout: fakeHead}},
		// git stash create
		shell.Call{Result: shell.Result{Stdout: fakeStash}},
		// git diff <headSHA> (rollback offer — always shown)
		shell.Call{Result: shell.Result{Stdout: ""}},
	)
	mr.AddArmedCall(makeArmedHandle(42), nil)

	stubNotifySend(t)
	cc, aud, p, buf := armTestCC(t, mr)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"sleep", "1"}, false)
	require.NoError(t, err)

	calls := mr.RecordedCalls()
	// Verify the first two RunWithEnv calls are git rev-parse and git stash create.
	require.GreaterOrEqual(t, len(calls), 2)
	assert.Equal(t, "git", calls[0].Name)
	assert.Equal(t, []string{"rev-parse", "HEAD"}, calls[0].Args)
	assert.Equal(t, "git", calls[1].Name)
	assert.Equal(t, []string{"stash", "create"}, calls[1].Args)
	// Stash was non-empty: assert the stash sha is stored (checked via rollback behavior).
	assert.Contains(t, buf.String(), "dry-run", "should show dry-run message when stash exists")
}

// TestArm_CleanTree verifies that when git stash create returns empty (clean
// working tree), runArm does not emit a rollback offer (Pitfall 4, D-08).
func TestArm_CleanTree(t *testing.T) {
	const fakeHead = "abc123def456"

	mr := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: fakeHead}}, // git rev-parse HEAD
		shell.Call{Result: shell.Result{Stdout: ""}},       // git stash create → empty (clean)
		shell.Call{Result: shell.Result{Stdout: ""}},       // git diff <headSHA>
	)
	mr.AddArmedCall(makeArmedHandle(42), nil)

	stubNotifySend(t)
	cc, aud, p, buf := armTestCC(t, mr)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"true"}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "clean at arm time", "should report clean working tree")
	assert.NotContains(t, output, "dry-run", "should NOT show dry-run rollback offer for clean tree")
	assert.NotContains(t, output, "--apply", "should NOT show --apply option for clean tree")
}

// TestArm_DryRunRollback verifies that when stashSHA is non-empty and apply=false,
// runArm shows the diff and "(dry-run)" message but does NOT call git stash apply (D-08).
func TestArm_DryRunRollback(t *testing.T) {
	const fakeHead = "abc123"
	const fakeStash = "stashSHA999"
	const fakeDiff = "--- a/file.go\n+++ b/file.go\n@@ -1 +1 @@\n-old\n+new\n"

	mr := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: fakeHead}},  // git rev-parse HEAD
		shell.Call{Result: shell.Result{Stdout: fakeStash}}, // git stash create
		shell.Call{Result: shell.Result{Stdout: fakeDiff}},  // git diff <headSHA>
	)
	mr.AddArmedCall(makeArmedHandle(42), nil)

	stubNotifySend(t)
	cc, aud, p, buf := armTestCC(t, mr)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"true"}, false /*apply=false*/)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, fakeDiff, "should show diff since arm time")
	assert.Contains(t, output, "dry-run", "should show dry-run message")
	assert.Contains(t, output, "--apply", "should mention --apply flag")

	// Verify git stash apply was NOT called.
	for _, c := range mr.RecordedCalls() {
		if c.Name == "git" && len(c.Args) >= 2 && c.Args[0] == "stash" && c.Args[1] == "apply" {
			t.Fatalf("git stash apply must NOT be called in dry-run mode; got: %v", c.Args)
		}
	}
}

// TestArm_ApplyRollback verifies that when stashSHA is non-empty, apply=true, and
// HEAD has not advanced, runArm calls git stash apply <stashSHA> (D-08, T-31-12).
func TestArm_ApplyRollback(t *testing.T) {
	const fakeHead = "abc123"
	const fakeStash = "stashSHA999"

	mr := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: fakeHead}},  // git rev-parse HEAD (arm time)
		shell.Call{Result: shell.Result{Stdout: fakeStash}}, // git stash create
		shell.Call{Result: shell.Result{Stdout: ""}},        // git diff <headSHA>
		shell.Call{Result: shell.Result{Stdout: fakeHead}},  // git rev-parse HEAD (advance check — same SHA)
		shell.Call{}, // git stash apply <stashSHA>
	)
	mr.AddArmedCall(makeArmedHandle(42), nil)

	stubNotifySend(t)
	cc, aud, p, buf := armTestCC(t, mr)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"true"}, true /*apply=true*/)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "restored to arm-time state", "should confirm rollback succeeded")

	// Verify git stash apply was called with the correct stash SHA.
	var foundApply bool
	for _, c := range mr.RecordedCalls() {
		if c.Name == "git" && len(c.Args) >= 3 && c.Args[0] == "stash" && c.Args[1] == "apply" {
			assert.Equal(t, fakeStash, c.Args[2], "stash apply must use arm-time stash SHA")
			foundApply = true
		}
	}
	assert.True(t, foundApply, "git stash apply must be called in --apply mode")
}

// TestArm_HeadAdvanced verifies that when HEAD has advanced since arm time and
// apply=true, runArm does NOT call git stash apply (T-31-12: HEAD-advance guard)
// and prints "WARNING: HEAD has advanced".
func TestArm_HeadAdvanced(t *testing.T) {
	const fakeHead = "abc123"
	const newHead = "xyz789" // different — HEAD advanced
	const fakeStash = "stashSHA999"

	mr := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: fakeHead}},  // git rev-parse HEAD (arm time)
		shell.Call{Result: shell.Result{Stdout: fakeStash}}, // git stash create
		shell.Call{Result: shell.Result{Stdout: ""}},        // git diff <headSHA>
		shell.Call{Result: shell.Result{Stdout: newHead}},   // git rev-parse HEAD (advance check — different SHA)
	)
	mr.AddArmedCall(makeArmedHandle(42), nil)

	stubNotifySend(t)
	cc, aud, p, buf := armTestCC(t, mr)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"true"}, true /*apply=true*/)
	require.NoError(t, err)

	output := buf.String()
	// T-31-12: HEAD-advance warning, rendered as a NoteWarn callout box.
	assert.Contains(t, output, "HEAD has advanced since arm", "should warn about HEAD advance")
	assert.Contains(t, output, "restore skipped", "should indicate restore was skipped")

	// Verify git stash apply was NOT called.
	for _, c := range mr.RecordedCalls() {
		if c.Name == "git" && len(c.Args) >= 2 && c.Args[0] == "stash" && c.Args[1] == "apply" {
			t.Fatalf("git stash apply must NOT be called when HEAD has advanced; got: %v", c.Args)
		}
	}
}

// --------------------------------------------------------------------------
// Task 3: CLI-level ladder regression test (KILL-01/KILL-02, CR-01).
//
// These tests exercise the PRODUCTION arm_cmd.go construction path: they call
// armSpawnWatchWait directly so the *approve.Registry and HMAC key come from the
// real wiring inside that function — never injected by the test. This is what
// the in-package budget_test.go could not cover (it injects a real registry,
// which is exactly why the nil-registry bug shipped). Reverting the Task 2
// wiring (nil registry) makes TestArm_LadderMode_ApproveResume FAIL.
// --------------------------------------------------------------------------

// ladderTestRunner is a shell.Runner that also satisfies shell.ArmedRunner and
// the local setObserver interface used by armSpawnWatchWait. It embeds a
// MockRunner for the plain Runner surface and adds a controllable ArmedHandle
// plus an observer seam so the test can push closure hashes to trip the loop.
type ladderTestRunner struct {
	*shell.MockRunner
	handle *shell.ArmedHandle

	mu  sync.Mutex
	obs func([32]byte)
}

// RunArmed returns the controllable handle (Done stays OPEN until the test
// closes it, so armSpawnWatchWait stays inside the ladder while frozen).
func (r *ladderTestRunner) RunArmed(_ context.Context, _ string, _ ...string) (*shell.ArmedHandle, error) {
	return r.handle, nil
}

// SetObserver records the budget watcher's loop-detection callback.
func (r *ladderTestRunner) SetObserver(fn func([32]byte)) {
	r.mu.Lock()
	r.obs = fn
	r.mu.Unlock()
}

// push delivers a closure hash to the registered observer (simulates an exec).
func (r *ladderTestRunner) push(h [32]byte) {
	r.mu.Lock()
	fn := r.obs
	r.mu.Unlock()
	if fn != nil {
		fn(h)
	}
}

// TestArm_LadderMode_ApproveResume drives the real arm_cmd.go wiring: with
// budget.ladder:true and a seeded audit-hmac key, armSpawnWatchWait builds a
// real registry (production path), trips the loop, sends SIGSTOP, opens an
// approve request, and — after the test resolves it approved via the PRODUCTION
// registry — sends SIGCONT. No nil-pointer panic. This FAILS on the pre-fix
// wiring (nil registry → panic / no SIGCONT) and PASSES after Task 2.
func TestArm_LadderMode_ApproveResume(t *testing.T) {
	stubNotifySend(t)

	// Ladder enabled, low loop window so 2 identical hashes trip quickly.
	cfg := config.Defaults()
	cfg.Budget = config.BudgetConfig{
		WallClockMinutes: 0, // ConfigFrom maps 0 → 30m default; harmless in a 3s test
		LoopN:            2,
		LoopWindow:       5,
		Ladder:           true,
		KillGraceSeconds: 1,
	}

	// Controllable handle whose Done stays OPEN until we observe SIGCONT.
	done := make(chan struct{})
	handle := &shell.ArmedHandle{
		PGID: 4242,
		Done: done,
		Wait: func() error { return nil },
	}
	runner := &ladderTestRunner{MockRunner: shell.NewMockRunner(), handle: handle}
	cc := &cmdContext{cfg: cfg, runner: runner}

	dir := t.TempDir()
	aud := audit.New(filepath.Join(dir, "audit.log"))
	// nm is unused by the stubbed notify seam (stubNotifySend), so nil is safe.
	var nm *notifymod.Module

	// Seed a real keychain with the audit-hmac key so the PRODUCTION load path runs.
	kc := secrets.NewMockStore()
	hmacKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i + 1)
	}
	require.NoError(t, kc.Set(context.Background(), "abysslink", "audit-hmac", hex.EncodeToString(hmacKey)))

	// Observe signals without touching a real process group.
	var sigMu sync.Mutex
	var sigs []syscall.Signal
	sigFn := func(_ int, sig syscall.Signal) error {
		sigMu.Lock()
		sigs = append(sigs, sig)
		sigMu.Unlock()
		return nil
	}
	hasSig := func(want syscall.Signal) bool {
		sigMu.Lock()
		defer sigMu.Unlock()
		for _, s := range sigs {
			if s == want {
				return true
			}
		}
		return false
	}

	// Capture the PRODUCTION-built watcher + registry via the test seam. The
	// test NEVER constructs its own registry — it resolves the production one.
	var prodReg *approve.Registry
	var prodWatcher *budget.Watcher
	var hookMu sync.Mutex
	armWatcherHook = func(w *budget.Watcher, reg *approve.Registry) {
		hookMu.Lock()
		prodWatcher, prodReg = w, reg
		hookMu.Unlock()
	}
	t.Cleanup(func() { armWatcherHook = nil })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	swwDone := make(chan error, 1)
	go func() {
		swwDone <- armSpawnWatchWait(ctx, cc, aud, nm, kc, sigFn,
			[]string{"loop-cmd"}, "" /*castPath*/, "" /*stashSHA*/, "armhash", false)
	}()

	// Wait until the watcher is constructed and the observer is registered.
	require.Eventually(t, func() bool {
		hookMu.Lock()
		defer hookMu.Unlock()
		return prodWatcher != nil && prodReg != nil
	}, 2*time.Second, 5*time.Millisecond, "production watcher/registry not constructed")

	// Trip the loop: 2 identical closure hashes.
	h := [32]byte{0xAB, 0xCD}
	runner.push(h)
	runner.push(h)

	// SIGSTOP must be observed (ladder froze the group).
	require.Eventually(t, func() bool { return hasSig(syscall.SIGSTOP) },
		2*time.Second, 10*time.Millisecond, "expected SIGSTOP after ladder trip")

	// Resolve the pending request as approved via the PRODUCTION registry.
	// The request opens asynchronously in the ladder goroutine after SIGSTOP, so
	// poll for it rather than reading once — the single-shot read raced on loaded
	// CI runners (observed flaky on macos-latest).
	var reqID string
	require.Eventually(t, func() bool {
		reqID = prodWatcher.LastRequestID()
		return reqID != ""
	}, 2*time.Second, 10*time.Millisecond, "expected a pending request ID after SIGSTOP (production registry opened a request)")
	require.True(t, prodReg.Resolve(reqID, approve.StateApproved), "resolve approved should succeed")

	// SIGCONT must follow the Approve tap — proving the approve loop is reachable.
	require.Eventually(t, func() bool { return hasSig(syscall.SIGCONT) },
		2*time.Second, 10*time.Millisecond, "expected SIGCONT after Approve via production registry")

	// No kill on approve.
	assert.False(t, hasSig(syscall.SIGKILL), "Approve must not trigger SIGKILL")

	// Let armSpawnWatchWait return by closing the process Done channel.
	close(done)
	select {
	case err := <-swwDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("armSpawnWatchWait did not return after process Done closed")
	}
}

// installTempDeadmanRegistry points armDeadmanRegistryFactory at a temp state
// file + temp audit log for the duration of t, returning the resolved registry
// so the test can inspect the on-disk state. Restores the production factory on
// cleanup.
func installTempDeadmanRegistry(t *testing.T) *deadman.Registry {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "armed-runs.json")
	aud := audit.New(filepath.Join(dir, "audit.log"))
	reg := deadman.New(statePath, aud)
	orig := armDeadmanRegistryFactory
	armDeadmanRegistryFactory = func() (*deadman.Registry, error) { return reg, nil }
	t.Cleanup(func() { armDeadmanRegistryFactory = orig })
	return reg
}

// TestArm_RegistersAndDeregistersPgid asserts that armSpawnWatchWait registers
// its pgid in the armed-run registry during the run and deregisters it after the
// armed process exits (SUPL-06).
func TestArm_RegistersAndDeregistersPgid(t *testing.T) {
	stubNotifySend(t)
	reg := installTempDeadmanRegistry(t)

	const fakePGID = 5150
	done := make(chan struct{})
	handle := &shell.ArmedHandle{
		PGID: fakePGID,
		Done: done,
		Wait: func() error { return nil },
	}
	runner := &ladderTestRunner{MockRunner: shell.NewMockRunner(), handle: handle}
	cc := &cmdContext{cfg: config.Defaults(), runner: runner}

	dir := t.TempDir()
	aud := audit.New(filepath.Join(dir, "audit.log"))
	var nm *notifymod.Module

	sigFn := func(_ int, _ syscall.Signal) error { return nil }

	swwDone := make(chan error, 1)
	go func() {
		swwDone <- armSpawnWatchWait(context.Background(), cc, aud, nm, nil /*kc*/, sigFn,
			[]string{"sleep"}, "" /*castPath*/, "" /*stashSHA*/, "armhash5150", false)
	}()

	// During the run the pgid must be in the registry's state file.
	require.Eventually(t, func() bool {
		runs, err := reg.List()
		if err != nil {
			return false
		}
		for _, r := range runs {
			if r.PGID == fakePGID {
				return true
			}
		}
		return false
	}, 2*time.Second, 5*time.Millisecond, "pgid should be registered during the armed run")

	// Process exits → deregister fires.
	close(done)
	select {
	case err := <-swwDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("armSpawnWatchWait did not return after process Done closed")
	}

	runs, err := reg.List()
	require.NoError(t, err)
	for _, r := range runs {
		require.NotEqual(t, fakePGID, r.PGID, "pgid must be deregistered after the armed process exits")
	}
}

// TestArm_RegistryFailureIsFailSoft asserts that a registry factory failure (or
// a Register failure) does NOT abort the arm — the kill-switch must stay usable
// even when the registry is unavailable (T-32-22, fail-soft).
func TestArm_RegistryFailureIsFailSoft(t *testing.T) {
	stubNotifySend(t)

	// Factory returns an error: registry unavailable.
	orig := armDeadmanRegistryFactory
	armDeadmanRegistryFactory = func() (*deadman.Registry, error) {
		return nil, errors.New("simulated registry wiring failure")
	}
	t.Cleanup(func() { armDeadmanRegistryFactory = orig })

	done := make(chan struct{})
	close(done) // process already exited — arm should complete cleanly
	handle := &shell.ArmedHandle{PGID: 6161, Done: done, Wait: func() error { return nil }}
	runner := &ladderTestRunner{MockRunner: shell.NewMockRunner(), handle: handle}
	cc := &cmdContext{cfg: config.Defaults(), runner: runner}

	dir := t.TempDir()
	aud := audit.New(filepath.Join(dir, "audit.log"))
	var nm *notifymod.Module
	sigFn := func(_ int, _ syscall.Signal) error { return nil }

	err := armSpawnWatchWait(context.Background(), cc, aud, nm, nil /*kc*/, sigFn,
		[]string{"true"}, "", "", "armhash6161", false)
	require.NoError(t, err, "a registry failure must NOT abort the arm (fail-soft)")
}

// spawnFailRunner is an ArmedRunner whose RunArmed fails the test if reached —
// used by the CR-03 lockdown-refusal tests to prove the armed process is NEVER
// spawned when arming is refused in the pre-flight.
type spawnFailRunner struct {
	*shell.MockRunner
	t *testing.T
}

func (r *spawnFailRunner) RunArmed(_ context.Context, _ string, _ ...string) (*shell.ArmedHandle, error) {
	r.t.Fatal("RunArmed must NOT be called: arm must refuse before spawning under lockdown")
	return nil, nil
}

// writeLockdownFlag writes a valid lockdown flag at path through a temp audit
// writer (deadman.SetLockdownFlag) so IsLockedDown parses it as locked.
func writeLockdownFlag(t *testing.T, flagPath, reason string) {
	t.Helper()
	dir := t.TempDir()
	aud := audit.New(filepath.Join(dir, "lockdown-audit.log"))
	require.NoError(t, deadman.SetLockdownFlag(context.Background(), flagPath, aud, reason, time.Now))
}

// TestArm_RefusesUnderLockdown is the CR-03 regression: with the dead-man
// lockdown flag SET, runArm must refuse to arm (returning an error that names
// the lockdown and points at the clear path) and must NEVER spawn the armed
// process. This FAILS against the pre-fix arm path (which ignored the flag and
// spawned) and PASSES after the lockdown pre-flight.
func TestArm_RefusesUnderLockdown(t *testing.T) {
	stubNotifySend(t)

	// Redirect the lockdown flag to a temp path and set it.
	dir := t.TempDir()
	flagPath := filepath.Join(dir, "deadman-lockdown.json")
	orig := armLockdownFlagPathFn
	armLockdownFlagPathFn = func() (string, error) { return flagPath, nil }
	t.Cleanup(func() { armLockdownFlagPathFn = orig })
	writeLockdownFlag(t, flagPath, "no-contact-timeout")

	runner := &spawnFailRunner{MockRunner: shell.NewMockRunner(), t: t}
	cc := &cmdContext{cfg: config.Defaults(), runner: runner}
	aud := audit.New(filepath.Join(dir, "audit.log"))
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"claude"}, false)
	require.Error(t, err, "arm must refuse while the dead-man lockdown flag is set")
	assert.Contains(t, err.Error(), "lockdown", "the refusal must name the dead-man lockdown")
	assert.Contains(t, err.Error(), "no-contact-timeout", "the refusal must include the lockdown reason")
}

// TestArm_ArmsAfterLockdownCleared asserts that once the lockdown flag is
// cleared (deadman.ClearLockdownFlag), runArm proceeds past the pre-flight and
// reaches the spawn path (no refusal).
func TestArm_ArmsAfterLockdownCleared(t *testing.T) {
	stubNotifySend(t)

	dir := t.TempDir()
	flagPath := filepath.Join(dir, "deadman-lockdown.json")
	orig := armLockdownFlagPathFn
	armLockdownFlagPathFn = func() (string, error) { return flagPath, nil }
	t.Cleanup(func() { armLockdownFlagPathFn = orig })

	// Set then clear the flag.
	writeLockdownFlag(t, flagPath, "no-contact-timeout")
	require.NoError(t, deadman.ClearLockdownFlag(flagPath))

	// A normal arm happy-path runner (clean tree → completes cleanly).
	mr := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "headSHA"}}, // git rev-parse HEAD
		shell.Call{Result: shell.Result{Stdout: ""}},        // git stash create → clean
		shell.Call{Result: shell.Result{Stdout: ""}},        // git diff
	)
	mr.AddArmedCall(makeArmedHandle(42), nil)
	cc := &cmdContext{cfg: config.Defaults(), runner: mr}
	aud := audit.New(filepath.Join(dir, "audit.log"))
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"true"}, false)
	require.NoError(t, err, "after clearing the lockdown flag, arm must proceed normally")
}

// TestArm_RefusesOnIndeterminateLockdown is the CR-03 fail-closed case: when the
// lockdown-flag read returns an ERROR (indeterminate state, not "absent"), arm
// must REFUSE rather than silently proceeding to spawn. The armed process is
// never reached.
func TestArm_RefusesOnIndeterminateLockdown(t *testing.T) {
	stubNotifySend(t)

	dir := t.TempDir()
	origPath := armLockdownFlagPathFn
	armLockdownFlagPathFn = func() (string, error) { return filepath.Join(dir, "deadman-lockdown.json"), nil }
	t.Cleanup(func() { armLockdownFlagPathFn = origPath })

	origIs := armIsLockedDown
	armIsLockedDown = func(string) (bool, string, error) {
		return false, "", errors.New("simulated lockdown-flag read failure")
	}
	t.Cleanup(func() { armIsLockedDown = origIs })

	runner := &spawnFailRunner{MockRunner: shell.NewMockRunner(), t: t}
	cc := &cmdContext{cfg: config.Defaults(), runner: runner}
	aud := audit.New(filepath.Join(dir, "audit.log"))
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)

	err := runArm(context.Background(), cc, nil, aud, p, nil /*kc*/, []string{"claude"}, false)
	require.Error(t, err, "arm must fail closed when the lockdown state is indeterminate (read error)")
	assert.Contains(t, err.Error(), "refusing", "the fail-closed refusal must be explicit")
}

// minimalRecordingRunner implements BOTH shell.ArmedRunner and
// shell.ArmedMinimalRunner and records which method the arm path invoked. It is
// used by the WR-01 routing test to prove Budget.MinimizeAgentEnv selects the
// minimized spawn.
type minimalRecordingRunner struct {
	*shell.MockRunner
	handle         *shell.ArmedHandle
	calledMinimal  bool
	calledRunArmed bool
}

func (r *minimalRecordingRunner) RunArmed(_ context.Context, _ string, _ ...string) (*shell.ArmedHandle, error) {
	r.calledRunArmed = true
	return r.handle, nil
}

func (r *minimalRecordingRunner) RunArmedMinimal(_ context.Context, _ string, _ ...string) (*shell.ArmedHandle, error) {
	r.calledMinimal = true
	return r.handle, nil
}

// TestArm_MinimizeAgentEnv_RoutesToMinimalSpawn is the WR-01 production-wiring
// regression: with Budget.MinimizeAgentEnv=true and a runner implementing
// ArmedMinimalRunner, armSpawnWatchWait must call RunArmedMinimal (not RunArmed);
// with the knob false it must call RunArmed. This proves the knob is a REAL
// production caller of the B10 minimized spawn, not a zero-caller capability.
func TestArm_MinimizeAgentEnv_RoutesToMinimalSpawn(t *testing.T) {
	stubNotifySend(t)

	run := func(t *testing.T, minimize bool) *minimalRecordingRunner {
		t.Helper()
		cfg := config.Defaults()
		cfg.Budget.MinimizeAgentEnv = minimize

		done := make(chan struct{})
		close(done) // process already exited so armSpawnWatchWait completes
		handle := &shell.ArmedHandle{PGID: 7272, Done: done, Wait: func() error { return nil }}
		runner := &minimalRecordingRunner{MockRunner: shell.NewMockRunner(), handle: handle}
		cc := &cmdContext{cfg: cfg, runner: runner}

		dir := t.TempDir()
		aud := audit.New(filepath.Join(dir, "audit.log"))
		var nm *notifymod.Module
		sigFn := func(_ int, _ syscall.Signal) error { return nil }

		err := armSpawnWatchWait(context.Background(), cc, aud, nm, nil /*kc*/, sigFn,
			[]string{"claude"}, "", "", "armhash7272", false)
		require.NoError(t, err)
		return runner
	}

	t.Run("knob on routes to minimal", func(t *testing.T) {
		runner := run(t, true)
		assert.True(t, runner.calledMinimal, "MinimizeAgentEnv=true must route to RunArmedMinimal")
		assert.False(t, runner.calledRunArmed, "MinimizeAgentEnv=true must NOT call RunArmed")
	})

	t.Run("knob off routes to RunArmed", func(t *testing.T) {
		runner := run(t, false)
		assert.True(t, runner.calledRunArmed, "MinimizeAgentEnv=false must route to RunArmed")
		assert.False(t, runner.calledMinimal, "MinimizeAgentEnv=false must NOT call RunArmedMinimal")
	})
}
