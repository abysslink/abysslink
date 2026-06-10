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

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/session"
)

// newBridgeServer wires a Server with a captureNotifier and the test-pinned
// hostname "rig-1" (the locked byte-exact title from phase success criterion
// 1 needs a deterministic host segment). INTERNAL test (package daemon): the
// hostname field and dispatcher are unexported.
func newBridgeServer(t *testing.T) (*Server, *captureNotifier) {
	t.Helper()
	n := &captureNotifier{}
	srv := NewServer(n, nil, nil)
	srv.hostname = "rig-1"
	return srv, n
}

// needsInputTransition is the canonical bridge-input fixture: %3 in $1/@2,
// epoch 1, claudecode, display names work/editor.
func needsInputTransition() session.Transition {
	return session.Transition{
		Type:        session.TransitionNeedsInput,
		SessionID:   "$1",
		WindowID:    "@2",
		PaneID:      "%3",
		Epoch:       1,
		Consumer:    "claudecode",
		SessionName: "work",
		WindowName:  "editor",
	}
}

// startBridge runs ConsumeTransitions over ch and returns a done channel that
// closes when the bridge goroutine returns.
func startBridge(ctx context.Context, srv *Server, ch <-chan session.Transition) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.ConsumeTransitions(ctx, ch)
	}()
	return done
}

// awaitNotes polls the captureNotifier until it has at least want notes (or
// the deadline passes) and returns everything captured.
func awaitNotes(t *testing.T, n *captureNotifier, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n.count() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d notes (got %d)", want, n.count())
}

// TestConsumeTransitions_NeedsInput: a NeedsInput transition becomes the
// locked compact title "rig-1 · claude · %3 needs input" with the D-19
// display-name breadcrumb "work › editor › %3" in the body — the full
// registry→phone seam minus live tmux/ntfy.
func TestConsumeTransitions_NeedsInput(t *testing.T) {
	srv, n := newBridgeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan session.Transition, 1)
	startBridge(ctx, srv, ch)

	ch <- needsInputTransition()
	awaitNotes(t, n, 1)

	notes := n.all()
	require.Len(t, notes, 1)
	assert.Equal(t, "rig-1 · claude · %3 needs input", notes[0].Title)
	assert.Contains(t, notes[0].Body, "work › editor › %3", "D-19 breadcrumb from RenderOpts display names")
	assert.Contains(t, notes[0].Body, "kind: needs_input")
	assert.Contains(t, notes[0].Body, "epoch 1")
}

// TestConsumeTransitions_RestartLost (D-29): a RestartLost transition is
// dispatched as kind agent_stopped with the locked title verb phrase and the
// session identity (OLD epoch) from the transition.
func TestConsumeTransitions_RestartLost(t *testing.T) {
	srv, n := newBridgeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan session.Transition, 1)
	startBridge(ctx, srv, ch)

	tr := needsInputTransition()
	tr.Type = session.TransitionRestartLost
	ch <- tr
	awaitNotes(t, n, 1)

	notes := n.all()
	require.Len(t, notes, 1)
	assert.Equal(t, "rig-1 · claude · %3 lost at tmux restart (was waiting for input)", notes[0].Title)
	assert.Contains(t, notes[0].Body, "kind: agent_stopped")
	assert.Contains(t, notes[0].Body, "ids: $1 @2 %3 epoch 1", "identity and OLD epoch from the transition")
	assert.Equal(t, "stop_sign", notes[0].Tags, "agent_stopped renders the D-21 stop_sign tag")
}

// TestConsumeTransitions_Cleared: TransitionCleared is state-only — zero
// dispatches (visibility lives on /sessions). A sentinel NeedsInput after it
// proves the loop kept consuming.
func TestConsumeTransitions_Cleared(t *testing.T) {
	srv, n := newBridgeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan session.Transition, 2)
	startBridge(ctx, srv, ch)

	cleared := needsInputTransition()
	cleared.Type = session.TransitionCleared
	ch <- cleared
	ch <- needsInputTransition() // sentinel
	awaitNotes(t, n, 1)

	notes := n.all()
	require.Len(t, notes, 1, "Cleared must produce zero dispatches")
	assert.True(t, strings.HasSuffix(notes[0].Title, "needs input"), "the only note is the sentinel")
}

// TestConsumeTransitions_ValidationSafety: a hand-built transition whose
// consumer fails the D-25 wire regex makes dispatch return a Validate error;
// the bridge logs and CONTINUES — one bad transition never stops the bridge.
func TestConsumeTransitions_ValidationSafety(t *testing.T) {
	srv, n := newBridgeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan session.Transition, 2)
	startBridge(ctx, srv, ch)

	bad := needsInputTransition()
	bad.Consumer = "FORCED-UPPER" // fails ^[a-z0-9_-]{1,32}$ (D-25)
	ch <- bad
	ch <- needsInputTransition() // must still flow after the bad one
	awaitNotes(t, n, 1)

	notes := n.all()
	require.Len(t, notes, 1, "the invalid transition must not dispatch")
	assert.Equal(t, "rig-1 · claude · %3 needs input", notes[0].Title)
}

// TestConsumeTransitions_LifecycleChannelClose: closing the events channel
// ends ConsumeTransitions cleanly.
func TestConsumeTransitions_LifecycleChannelClose(t *testing.T) {
	srv, _ := newBridgeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan session.Transition)
	done := startBridge(ctx, srv, ch)

	close(ch)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ConsumeTransitions did not return after channel close")
	}
}

// TestConsumeTransitions_LifecycleCtxCancel: cancelling ctx ends
// ConsumeTransitions cleanly even with the channel still open.
func TestConsumeTransitions_LifecycleCtxCancel(t *testing.T) {
	srv, _ := newBridgeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan session.Transition)
	done := startBridge(ctx, srv, ch)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ConsumeTransitions did not return after ctx cancel")
	}
}
