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

package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// loadFixture loads a committed testdata transcript.
func loadFixture(t *testing.T, name string) *shell.Transcript {
	t.Helper()
	tr, err := shell.LoadTranscript(filepath.Join("testdata", name))
	require.NoError(t, err)
	return tr
}

// writeTranscript materializes an inline D-35 script as a temp fixture for
// timing-sensitive cases the committed fixtures do not cover.
func writeTranscript(t *testing.T, content string) *shell.Transcript {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inline.transcript")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	tr, err := shell.LoadTranscript(p)
	require.NoError(t, err)
	return tr
}

// sleepRecorder replaces Registry.sleep so no supervisor test ever really
// waits (RESEARCH Pitfall 9). It records the requested duration and the
// registry status AT SLEEP TIME (the supervisor sets status right before
// backing off), and cancels the run context after cancelAfter records.
type sleepRecorder struct {
	mu          sync.Mutex
	durations   []time.Duration
	statuses    []string
	cancelAfter int
	cancel      context.CancelFunc
	r           *Registry
}

func (s *sleepRecorder) sleep(_ context.Context, d time.Duration) {
	s.mu.Lock()
	s.durations = append(s.durations, d)
	s.statuses = append(s.statuses, s.r.Snapshot().Status)
	n := len(s.durations)
	s.mu.Unlock()
	if n >= s.cancelAfter {
		s.cancel()
	}
}

func (s *sleepRecorder) recorded() ([]time.Duration, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := make([]time.Duration, len(s.durations))
	copy(d, s.durations)
	st := make([]string, len(s.statuses))
	copy(st, s.statuses)
	return d, st
}

// runSupervisor starts r.Run and returns a channel carrying its result.
func runSupervisor(ctx context.Context, r *Registry) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	return done
}

func waitDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err, "Run must exit cleanly on ctx cancel")
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not exit after ctx cancel")
	}
}

// TestSupervisorVersionGateUnsupported: tmux 3.1 is refused BEFORE any
// attach — RunStream is never called (Pitfall 3), the status carries the
// exact unsupported string (D-27), and the supervisor keeps re-checking on
// its backoff cadence so a tmux upgrade is picked up without a daemon
// restart.
func TestSupervisorVersionGateUnsupported(t *testing.T) {
	m := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "tmux 3.1c\n"}},
		shell.Call{Result: shell.Result{Stdout: "tmux 3.1c\n"}},
	)
	r := New(m, config.Defaults())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &sleepRecorder{cancelAfter: 2, cancel: cancel, r: r}
	r.sleep = rec.sleep

	done := runSupervisor(ctx, r)
	waitDone(t, done)

	_, statuses := rec.recorded()
	require.GreaterOrEqual(t, len(statuses), 2, "supervisor must keep re-checking the version gate")
	assert.Equal(t, "tmux: unsupported (3.1, need >= 3.2)", statuses[0])
	assert.Equal(t, "tmux: unsupported (3.1, need >= 3.2)", statuses[1])
	assert.Empty(t, m.StreamCalls(), "RunStream must NEVER be called for tmux < 3.2")
}

// TestSupervisorTmuxMissing: tmux absent degrades to "tmux: unavailable"
// with backoff retries — the daemon is never hostage to tmux (D-26).
func TestSupervisorTmuxMissing(t *testing.T) {
	m := shell.NewMockRunner(
		shell.Call{Err: errors.New("exec: \"tmux\": executable file not found in $PATH")},
		shell.Call{Err: errors.New("exec: \"tmux\": executable file not found in $PATH")},
	)
	r := New(m, config.Defaults())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &sleepRecorder{cancelAfter: 2, cancel: cancel, r: r}
	r.sleep = rec.sleep

	done := runSupervisor(ctx, r)
	waitDone(t, done)

	_, statuses := rec.recorded()
	require.GreaterOrEqual(t, len(statuses), 2)
	assert.Equal(t, StatusUnavailable, statuses[0])
	assert.Equal(t, StatusUnavailable, statuses[1])
	assert.Empty(t, m.StreamCalls())
}

// TestSupervisorAttachSnapshot: version 3.6b passes the gate, the attach
// rides RunStream with the structural no-output client flag, epoch becomes
// 1, status "ok", and the immediate list-panes poll populates the Snapshot.
func TestSupervisorAttachSnapshot(t *testing.T) {
	baseline := runtime.NumGoroutine()

	panes := paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor") + "\n" +
		paneLine("$1", "@1", "%2", "0", "0", "1", "claude", "work", "editor") + "\n"
	m := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "tmux 3.6b\n"}}, // version gate
		shell.Call{Result: shell.Result{Stdout: panes}},         // initial full poll
	)
	m.AddStream(loadFixture(t, "attach-basic.transcript"))

	r := New(m, config.Defaults())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.sleep = func(ctx context.Context, _ time.Duration) { <-ctx.Done() } // park on any failure

	done := runSupervisor(ctx, r)

	require.Eventually(t, func() bool {
		s := r.Snapshot()
		return s.Epoch == 1 && s.Status == StatusOK && len(s.Sessions) == 1
	}, 3*time.Second, 10*time.Millisecond, "attach must bump epoch to 1, set status ok, and snapshot panes")

	snap := r.Snapshot()
	assert.Equal(t, "3.6b", snap.TmuxVersion)
	require.Len(t, snap.Sessions[0].Windows, 1)
	require.Len(t, snap.Sessions[0].Windows[0].Panes, 2)
	assert.Equal(t, "shell", snap.Sessions[0].Windows[0].Panes[0].Consumer)
	assert.Equal(t, "claude", snap.Sessions[0].Windows[0].Panes[1].Consumer)

	// The attach is structurally %output-free: the no-output client flag is
	// part of the argv (BACK-03), not a parse-and-drop.
	calls := m.StreamCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"tmux", "-CC", "-u", "attach-session", "-f", "no-output"}, calls[0])

	cancel()
	waitDone(t, done)

	// Goroutine hygiene: Run's return leaves nothing behind. Polled on the
	// test goroutine itself (the stream_test idiom) — an Eventually-spawned
	// condition goroutine would inflate the count it is measuring.
	for i := 0; i < 100; i++ {
		if runtime.NumGoroutine() <= baseline {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), baseline, "no goroutines may outlive Run")
}

// TestSupervisorRestartEpochBumpAndDebounce: the restart transcript ends
// with %exit — the supervisor must re-attach (epoch 1 → 2) and re-snapshot.
// The two back-to-back structural events in the transcript must coalesce
// into exactly ONE debounced list-panes re-poll (two events, one poll).
func TestSupervisorRestartEpochBumpAndDebounce(t *testing.T) {
	paneA := paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor") + "\n"
	paneB := paneLine("$2", "@5", "%7", "0", "1", "1", "claude", "fresh", "main") + "\n"
	m := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "tmux 3.6b\n"}}, // gate, attach 1
		shell.Call{Result: shell.Result{Stdout: paneA}},         // initial poll, epoch 1
		shell.Call{Result: shell.Result{Stdout: paneA}},         // ONE debounced re-poll for TWO events
		shell.Call{Result: shell.Result{Stdout: "tmux 3.6b\n"}}, // gate, attach 2 (after %exit)
		shell.Call{Result: shell.Result{Stdout: paneB}},         // initial poll, epoch 2
	)
	m.AddStream(loadFixture(t, "restart.transcript"))
	m.AddStream(loadFixture(t, "attach-basic.transcript"))

	r := New(m, config.Defaults())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.sleep = func(ctx context.Context, _ time.Duration) { <-ctx.Done() }

	done := runSupervisor(ctx, r)

	require.Eventually(t, func() bool {
		s := r.Snapshot()
		return s.Epoch == 2 && s.Status == StatusOK && len(s.Sessions) == 1
	}, 5*time.Second, 10*time.Millisecond, "supervisor must survive %exit with an epoch bump and re-snapshot")

	snap := r.Snapshot()
	assert.Equal(t, "$2", snap.Sessions[0].ID, "state must be re-snapshotted from the new server")

	// Exactly: 2 version gates, 3 list-panes polls (initial + one debounced
	// for the two-event burst + initial after re-attach). The strict FIFO
	// mock makes any extra poll a hard failure upstream.
	var gates, polls int
	for _, argv := range m.RunCalls() {
		switch {
		case len(argv) == 2 && argv[1] == "-V":
			gates++
		case len(argv) > 1 && argv[1] == "list-panes":
			polls++
		}
	}
	assert.Equal(t, 2, gates)
	assert.Equal(t, 3, polls, "two structural events must coalesce into one debounced poll")
	assert.Len(t, m.StreamCalls(), 2, "one re-attach after %exit")

	cancel()
	waitDone(t, done)
}

// TestSupervisorBackoffResetAfterSuccess: a failure (1s), then a successful
// attach, then another failure — the second failure must back off at the
// base 1s again, not the doubled value.
func TestSupervisorBackoffResetAfterSuccess(t *testing.T) {
	paneA := paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor") + "\n"
	m := shell.NewMockRunner(
		shell.Call{Err: errors.New("no tmux")},                  // gate fail -> sleep 1s
		shell.Call{Result: shell.Result{Stdout: "tmux 3.6b\n"}}, // gate ok
		shell.Call{Result: shell.Result{Stdout: paneA}},         // initial poll
		shell.Call{Err: errors.New("no tmux")},                  // gate fail after stream end -> sleep must be 1s again
	)
	// The inline transcript closes immediately: greeting only, end-of-script.
	m.AddStream(writeTranscript(t, "<< %begin 1700000000 1 0\n<< %end 1700000000 1 0\n"))

	r := New(m, config.Defaults())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &sleepRecorder{cancelAfter: 2, cancel: cancel, r: r}
	r.sleep = rec.sleep

	done := runSupervisor(ctx, r)
	waitDone(t, done)

	durations, _ := rec.recorded()
	require.Len(t, durations, 2)
	assert.Equal(t, time.Second, durations[0])
	assert.Equal(t, time.Second, durations[1], "backoff must reset to base after a successful attach")
}

// TestSupervisorBackoffCap: repeated failures double the delay and cap at
// 30s — asserted via the injected sleep, no real waiting (Pitfall 9).
func TestSupervisorBackoffCap(t *testing.T) {
	calls := make([]shell.Call, 8)
	for i := range calls {
		calls[i] = shell.Call{Err: errors.New("no tmux")}
	}
	m := shell.NewMockRunner(calls...)

	r := New(m, config.Defaults())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &sleepRecorder{cancelAfter: 8, cancel: cancel, r: r}
	r.sleep = rec.sleep

	done := runSupervisor(ctx, r)
	waitDone(t, done)

	durations, _ := rec.recorded()
	require.Len(t, durations, 8)
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second,
	}
	assert.Equal(t, want, durations, "exponential backoff must cap at 30s (T-27-11)")
}
