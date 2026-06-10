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

package notifyv2_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

// renderMsg returns the canonical needs_input message used across the
// renderer tests.
func renderMsg() notifyv2.Message {
	return notifyv2.Message{
		V:        2,
		MsgID:    validULID,
		Kind:     notifyv2.KindNeedsInput,
		Host:     "rig-1",
		Consumer: "claudecode",
		Session:  notifyv2.SessionRef{Pane: "%3"},
		Title:    "needs input",
	}
}

// TestRender_LockedTitle asserts the phase's locked compact title form
// byte-exactly (phase success criterion 1).
func TestRender_LockedTitle(t *testing.T) {
	note := notifyv2.Render(renderMsg(), notifyv2.RenderOpts{})
	assert.Equal(t, "rig-1 · claude · %3 needs input", note.Title)
}

func TestRender_ConsumerDisplay(t *testing.T) {
	cases := []struct {
		name     string
		consumer string
		want     string
	}{
		{"claudecode maps to claude", "claudecode", "rig-1 · claude · %3 needs input"},
		{"unknown consumer verbatim", "aider", "rig-1 · aider · %3 needs input"},
		{"empty consumer omits segment", "", "rig-1 · %3 needs input"},
		{"zsh normalizes to shell (D-23 defense in depth)", "zsh", "rig-1 · shell · %3 needs input"},
		{"bash normalizes to shell", "bash", "rig-1 · shell · %3 needs input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := renderMsg()
			m.Consumer = tc.consumer
			note := notifyv2.Render(m, notifyv2.RenderOpts{})
			assert.Equal(t, tc.want, note.Title)
		})
	}
}

func TestRender_NoSessionIdentity(t *testing.T) {
	m := renderMsg()
	m.Consumer = ""
	m.Session = notifyv2.SessionRef{}
	note := notifyv2.Render(m, notifyv2.RenderOpts{})
	assert.Equal(t, "rig-1 · needs input", note.Title,
		"host + verb phrase; never a bare \"agent needs you\"")
}

func TestRender_BodyBreadcrumbAndMetadata(t *testing.T) {
	m := renderMsg()
	m.Session = notifyv2.SessionRef{Session: "$1", Window: "@2", Pane: "%3", Epoch: 1}
	note := notifyv2.Render(m, notifyv2.RenderOpts{SessionName: "work", WindowName: "editor"})

	assert.Contains(t, note.Body, "work › editor › %3", "display-name breadcrumb (D-19)")
	assert.Contains(t, note.Body, "needs_input", "kind line")
	assert.Contains(t, note.Body, "rig-1", "host line")
	assert.Contains(t, note.Body, "$1", "raw session id")
	assert.Contains(t, note.Body, "@2", "raw window id")
	assert.Contains(t, note.Body, "epoch 1", "epoch in the IDs line")
}

func TestRender_DisplayNameTruncationRuneSafe(t *testing.T) {
	m := renderMsg()
	longCJK := strings.Repeat("界", 40)   // 40 runes, 120 bytes
	longEmoji := strings.Repeat("🚀", 40) // 40 runes, 160 bytes
	note := notifyv2.Render(m, notifyv2.RenderOpts{SessionName: longCJK, WindowName: longEmoji})

	require.True(t, strings.Contains(note.Body, strings.Repeat("界", 32)),
		"session display name kept to 32 runes")
	assert.False(t, strings.Contains(note.Body, strings.Repeat("界", 33)),
		"session display name truncated at 32 runes")
	require.True(t, strings.Contains(note.Body, strings.Repeat("🚀", 32)),
		"window display name kept to 32 runes")
	assert.False(t, strings.Contains(note.Body, strings.Repeat("🚀", 33)),
		"window display name truncated at 32 runes")
	// Rune-safety: the body must remain valid UTF-8 with no broken sequences.
	assert.True(t, strings.ToValidUTF8(note.Body, "") == note.Body,
		"truncation must never byte-slice a rune")
}

func TestRender_PriorityMapping(t *testing.T) {
	cases := []struct {
		kind     notifyv2.Kind
		priority string
		want     string
	}{
		{notifyv2.KindApprovalRequest, "", "5"},
		{notifyv2.KindApprovalRequest, "high", "5"},
		{notifyv2.KindApprovalRequest, "normal", "5"},
		{notifyv2.KindNeedsInput, "high", "4"},
		{notifyv2.KindNeedsInput, "", "3"},
		{notifyv2.KindCommandDone, "normal", "3"},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind)+"/"+tc.priority, func(t *testing.T) {
			m := renderMsg()
			m.Kind = tc.kind
			m.Priority = tc.priority
			note := notifyv2.Render(m, notifyv2.RenderOpts{})
			assert.Equal(t, tc.want, note.Priority, "D-14 priority map")
		})
	}
}

func TestRender_KindTags(t *testing.T) {
	cases := []struct {
		kind notifyv2.Kind
		want string
	}{
		{notifyv2.KindNeedsInput, "question"},
		{notifyv2.KindCommandDone, "white_check_mark"},
		{notifyv2.KindApprovalRequest, "closed_lock_with_key"},
		{notifyv2.KindWatchFired, "eyes"},
		// docs.ntfy.sh/emojis has no "octagonal_sign"; the 🛑 shortcode is
		// "stop_sign" (verified 2026-06-10 — research assumption A2).
		{notifyv2.KindAgentStopped, "stop_sign"},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			m := renderMsg()
			m.Kind = tc.kind
			note := notifyv2.Render(m, notifyv2.RenderOpts{})
			assert.Equal(t, tc.want, note.Tags, "D-21 kind→emoji tag map")
		})
	}
}

func TestRender_ClickPassthrough(t *testing.T) {
	note := notifyv2.Render(renderMsg(), notifyv2.RenderOpts{Click: "ssh://mo@rig-1"})
	assert.Equal(t, "ssh://mo@rig-1", note.Click, "D-16 click passthrough")

	empty := notifyv2.Render(renderMsg(), notifyv2.RenderOpts{})
	assert.Empty(t, empty.Click)
}

// TestRender_ActionsDropped asserts D-18: actions are typed on the wire but
// the ntfy renderer drops them entirely — no representation anywhere in the
// note, and RenderedNote has no actions field at all this phase.
func TestRender_ActionsDropped(t *testing.T) {
	m := renderMsg()
	m.Actions = []notifyv2.Action{{ID: "approve", Label: "Approve"}, {ID: "deny", Label: "Deny"}}
	note := notifyv2.Render(m, notifyv2.RenderOpts{})

	for _, field := range []string{note.Title, note.Body, note.Priority, note.Tags, note.Click} {
		assert.NotContains(t, strings.ToLower(field), "approve")
		assert.NotContains(t, strings.ToLower(field), "deny")
	}

	typ := reflect.TypeOf(notifyv2.RenderedNote{})
	require.Equal(t, 5, typ.NumField(), "RenderedNote has exactly 5 fields")
	wantFields := []string{"Title", "Body", "Priority", "Tags", "Click"}
	for i, name := range wantFields {
		assert.Equal(t, name, typ.Field(i).Name)
	}
}
