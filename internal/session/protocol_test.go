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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParserSequence drives the control-mode state machine through every
// line shape: notification outside a block, %begin/%end bracketing,
// in-block reply payload, %error exit flavor, and unknown-line skip
// (RESEARCH Pattern 4 / Pitfall 4).
func TestParserSequence(t *testing.T) {
	p := &parser{}

	// Outside a block: %-prefixed lines are out-of-band notifications.
	ev := p.feed("%session-changed $1 work")
	assert.Equal(t, eventNotification, ev.kind)
	assert.Equal(t, "%session-changed", ev.name)
	assert.Equal(t, "$1 work", ev.rest)

	// %begin enters block state.
	ev = p.feed("%begin 1700000000 1 0")
	assert.Equal(t, eventBlockBegin, ev.kind)

	// Inside the block every line is reply payload — even %-prefixed ones
	// (notifications never occur inside %begin/%end blocks).
	ev = p.feed("$1 @1 %1 some reply payload")
	assert.Equal(t, eventReply, ev.kind)
	ev = p.feed("%not-a-notification inside block")
	assert.Equal(t, eventReply, ev.kind)

	// %end exits block state.
	ev = p.feed("%end 1700000000 1 0")
	assert.Equal(t, eventBlockEnd, ev.kind)

	// %error exits with the error flavor.
	ev = p.feed("%begin 1700000000 2 0")
	assert.Equal(t, eventBlockBegin, ev.kind)
	ev = p.feed("%error 1700000000 2 0")
	assert.Equal(t, eventBlockError, ev.kind)

	// Unknown non-% line outside a block: skipped, never an error
	// (RESEARCH Pitfall 4 — tmux output must never take the parser down).
	ev = p.feed("*** weird")
	assert.Equal(t, eventSkip, ev.kind)

	// Back to notifications after the blocks.
	ev = p.feed("%window-add @4")
	assert.Equal(t, eventNotification, ev.kind)
	assert.Equal(t, "%window-add", ev.name)
	assert.Equal(t, "@4", ev.rest)

	// Unknown notification names still classify as notifications — the
	// supervisor decides structural-vs-skip (tmux adds notifications
	// across versions).
	ev = p.feed("%future-thing a b c")
	assert.Equal(t, eventNotification, ev.kind)
	assert.Equal(t, "%future-thing", ev.name)
}

// TestParserStructuralNames pins the set of notifications that trigger a
// re-poll (events trigger polls; polls write state).
func TestParserStructuralNames(t *testing.T) {
	for _, name := range []string{
		"%sessions-changed", "%session-changed", "%session-renamed",
		"%window-add", "%window-close", "%window-renamed",
		"%unlinked-window-add", "%unlinked-window-close", "%unlinked-window-renamed",
		"%layout-change", "%client-detached", "%client-session-changed",
	} {
		assert.True(t, structuralNotifications[name], "expected %s to be structural", name)
	}
	assert.False(t, structuralNotifications["%exit"], "%%exit marks stream end, not a re-poll trigger")
	assert.False(t, structuralNotifications["%output"], "%%output is structurally suppressed (no-output flag), never polled on")
}

// TestParseTmuxVersion covers the mirrored parser (attribution: mirrors
// internal/modules/tmux.parseTmuxVersion), including suffix-letter versions.
func TestParseTmuxVersion(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
	}{
		{"tmux 3.3a", 3, 3},
		{"tmux 3.6b", 3, 6},
		{"tmux 3.1c", 3, 1},
		{"tmux 3.2", 3, 2},
		// tmux master builds: the next- prefix must be stripped so a
		// development build of a >= 3.2 tmux passes the version gate.
		{"tmux next-3.4", 3, 4},
		{"tmux next-3.6a", 3, 6},
	}
	for _, tc := range cases {
		major, minor, err := parseTmuxVersion(tc.in)
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.major, major, tc.in)
		assert.Equal(t, tc.minor, minor, tc.in)
	}

	for _, bad := range []string{"", "garbage", "tmux", "tmux three.two"} {
		_, _, err := parseTmuxVersion(bad)
		require.Error(t, err, "input %q must not parse", bad)
	}
}
