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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// paneLine builds one list-panes output line in the exact listPanesFormat
// field order: session_id, window_id, pane_id, alternate_on, pane_active,
// session_attached, pane_current_command, session_name, window_name.
func paneLine(fields ...string) string {
	return strings.Join(fields, "\t")
}

func newTestRegistry() *Registry {
	return New(shell.NewMockRunner(), config.Defaults())
}

func TestRegistrySyncPanesSnapshot(t *testing.T) {
	r := newTestRegistry()
	r.syncPanes([]string{
		paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor"),
		paneLine("$1", "@1", "%2", "1", "0", "1", "claude", "work", "editor"),
	})

	snap := r.Snapshot()
	require.Len(t, snap.Sessions, 1)
	s := snap.Sessions[0]
	assert.Equal(t, "$1", s.ID)
	assert.Equal(t, "work", s.Name)
	assert.Equal(t, 1, s.Attached)
	require.Len(t, s.Windows, 1)
	w := s.Windows[0]
	assert.Equal(t, "@1", w.ID)
	assert.Equal(t, "editor", w.Name)
	require.Len(t, w.Panes, 2)

	p1, p2 := w.Panes[0], w.Panes[1]
	assert.Equal(t, "%1", p1.ID)
	assert.True(t, p1.Active)
	assert.False(t, p1.AlternateOn)
	assert.Equal(t, "shell", p1.Consumer, "D-23: zsh normalizes to shell")
	assert.Equal(t, "%2", p2.ID)
	assert.False(t, p2.Active)
	assert.True(t, p2.AlternateOn)
	assert.Equal(t, "claude", p2.Consumer, "D-23: non-shell command passes through")
}

func TestRegistrySyncSkipsMalformedLines(t *testing.T) {
	r := newTestRegistry()
	r.syncPanes([]string{
		"only\ttwo", // too few fields
		paneLine("bogus", "@1", "%9", "0", "1", "1", "zsh", "a", "b"),       // session ID fails ^\$\d+$
		paneLine("$1", "w1", "%8", "0", "1", "1", "zsh", "a", "b"),          // window ID fails ^@\d+$
		paneLine("$1", "@1", "%-1", "0", "1", "1", "zsh", "a", "b"),         // pane ID fails ^%\d+$
		paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor"),  // valid
		"",                                                                  // blank line (empty poll tail)
	})

	snap := r.Snapshot()
	require.Len(t, snap.Sessions, 1)
	require.Len(t, snap.Sessions[0].Windows, 1)
	require.Len(t, snap.Sessions[0].Windows[0].Panes, 1)
	assert.Equal(t, "%1", snap.Sessions[0].Windows[0].Panes[0].ID)
}

func TestRegistrySyncDiffRemovesVanishedPane(t *testing.T) {
	r := newTestRegistry()
	r.syncPanes([]string{
		paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor"),
		paneLine("$1", "@2", "%2", "0", "0", "1", "vim", "work", "scratch"),
	})
	require.Len(t, r.Snapshot().Sessions[0].Windows, 2)

	// Second sync omits %2 entirely: the poll is the source of truth.
	r.syncPanes([]string{
		paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor"),
	})
	snap := r.Snapshot()
	require.Len(t, snap.Sessions, 1)
	require.Len(t, snap.Sessions[0].Windows, 1)
	assert.Equal(t, "@1", snap.Sessions[0].Windows[0].ID)
}

func TestRegistrySnapshotDeepCopy(t *testing.T) {
	r := newTestRegistry()
	r.syncPanes([]string{
		paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor"),
	})

	snap := r.Snapshot()
	snap.Sessions[0].Name = "mutated"
	snap.Sessions[0].Windows[0].Name = "mutated"
	snap.Sessions[0].Windows[0].Panes[0].Consumer = "mutated"

	snap2 := r.Snapshot()
	assert.Equal(t, "work", snap2.Sessions[0].Name, "Snapshot must return a deep copy")
	assert.Equal(t, "editor", snap2.Sessions[0].Windows[0].Name)
	assert.Equal(t, "shell", snap2.Sessions[0].Windows[0].Panes[0].Consumer)
}

func TestRegistrySyncPreservesHeuristicFieldsSameEpoch(t *testing.T) {
	r := newTestRegistry()
	line := paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor")
	r.syncPanes([]string{line})

	since := time.Now()
	r.mu.Lock()
	r.panes["%1"].needsInput = true
	r.panes["%1"].needsInputSince = since
	r.mu.Unlock()

	// Re-sync within the same epoch: heuristic fields must survive.
	r.syncPanes([]string{line})
	p := r.Snapshot().Sessions[0].Windows[0].Panes[0]
	assert.True(t, p.NeedsInput)
	assert.Equal(t, since, p.NeedsInputSince)
}

func TestRegistrySyncNewEpochClearsHeuristicFields(t *testing.T) {
	r := newTestRegistry()
	line := paneLine("$1", "@1", "%1", "0", "1", "1", "zsh", "work", "editor")
	r.syncPanes([]string{line})

	r.mu.Lock()
	r.panes["%1"].needsInput = true
	r.panes["%1"].needsInputSince = time.Now()
	r.mu.Unlock()

	// Epoch bump (tmux restart): pane %1 in the new epoch is a DIFFERENT pane
	// (Pitfall 5) — heuristic state must not leak across epochs.
	r.bumpEpoch()
	r.syncPanes([]string{line})
	p := r.Snapshot().Sessions[0].Windows[0].Panes[0]
	assert.False(t, p.NeedsInput)
	assert.True(t, p.NeedsInputSince.IsZero())
}

func TestRegistryNormalizeConsumer(t *testing.T) {
	cases := map[string]string{
		"zsh":          "shell",
		"bash":         "shell",
		"fish":         "shell",
		"sh":           "shell",
		"claude":       "claude",
		"node":         "node",
		"Claude Code!": "claudecode",
		"":             "",
		"///":          "",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeConsumer(in), "input %q", in)
	}
	// Cap at 32 so the daemon-side Message.Consumer always passes D-25.
	long := strings.Repeat("x", 40)
	assert.Equal(t, strings.Repeat("x", 32), normalizeConsumer(long))
}

func TestRegistryEventsBoundedDrop(t *testing.T) {
	r := newTestRegistry()
	// Over-fill the bounded channel: emit must drop, never block the caller
	// (T-27-11 — the poll loop is never hostage to a slow consumer).
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < eventsChanDepth+5; i++ {
			r.emit(Transition{Type: TransitionNeedsInput, PaneID: "%1", Epoch: 1})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit blocked on a full Events channel")
	}
	assert.Len(t, r.events, eventsChanDepth)

	tr := <-r.Events()
	assert.Equal(t, TransitionNeedsInput, tr.Type)
	assert.Equal(t, "%1", tr.PaneID)
	assert.Equal(t, uint64(1), tr.Epoch)
}

func TestRegistryTransitionTypesStable(t *testing.T) {
	// The channel contract (consumed by plans 27-06/27-07) defines exactly
	// these transition types now, even though emission lands later.
	assert.NotEqual(t, TransitionNeedsInput, TransitionCleared)
	assert.NotEqual(t, TransitionCleared, TransitionRestartLost)
	assert.NotEqual(t, TransitionNeedsInput, TransitionRestartLost)
}
