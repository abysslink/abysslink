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

// TestRender_ActionsDropped_NoURL asserts D-18 no-dead-buttons: actions without
// a URL (not yet wired to the content store) are dropped — no representation
// anywhere in the string fields, and Actions is nil.
func TestRender_ActionsDropped_NoURL(t *testing.T) {
	m := renderMsg()
	m.Kind = notifyv2.KindApprovalRequest
	m.Title = "approval required"
	// Actions without URL — these should be dropped (D-18 no dead buttons).
	m.Actions = []notifyv2.Action{{ID: "approve", Label: "Approve"}, {ID: "deny", Label: "Deny"}}
	note := notifyv2.Render(m, notifyv2.RenderOpts{})

	for _, field := range []string{note.Title, note.Body, note.Priority, note.Tags, note.Click} {
		assert.NotContains(t, strings.ToLower(field), "approve",
			"string fields must not contain approve button text")
		assert.NotContains(t, strings.ToLower(field), "deny",
			"string fields must not contain deny button text")
	}
	assert.Nil(t, note.Actions, "Actions must be nil when no URL is populated")
}

// TestRender_RenderedNoteFields verifies RenderedNote struct shape (Phase 30:
// 6 fields including Actions).
func TestRender_RenderedNoteFields(t *testing.T) {
	typ := reflect.TypeFor[notifyv2.RenderedNote]()
	require.Equal(t, 6, typ.NumField(), "RenderedNote has exactly 6 fields after Phase 30")
	wantFields := []string{"Title", "Body", "Priority", "Tags", "Click", "Actions"}
	for i, name := range wantFields {
		assert.Equal(t, name, typ.Field(i).Name)
	}
}

// TestRender_ApprovalRequest_Actions: KindApprovalRequest with URL-populated
// actions → note.Actions has 2 entries with correct Label+URL (D-18 un-drop).
func TestRender_ApprovalRequest_Actions(t *testing.T) {
	m := notifyv2.Message{
		V:     2,
		MsgID: validULID,
		Kind:  notifyv2.KindApprovalRequest,
		Host:  "rig-1",
		Title: "approval required",
		Actions: []notifyv2.Action{
			{ID: "approve", Label: "Approve", URL: "https://example.ts.net/approve/ablk_ok_xxx"},
			{ID: "deny", Label: "Deny", URL: "https://example.ts.net/deny/ablk_no_yyy"},
		},
	}
	note := notifyv2.Render(m, notifyv2.RenderOpts{})

	require.Len(t, note.Actions, 2, "both actions must be rendered")
	assert.Equal(t, "Approve", note.Actions[0].Label)
	assert.Equal(t, "https://example.ts.net/approve/ablk_ok_xxx", note.Actions[0].URL)
	assert.Equal(t, "Deny", note.Actions[1].Label)
	assert.Equal(t, "https://example.ts.net/deny/ablk_no_yyy", note.Actions[1].URL)
}

// TestRender_OtherKind_NoActions: non-approval messages have nil Actions.
func TestRender_OtherKind_NoActions(t *testing.T) {
	m := notifyv2.Message{
		V:     2,
		MsgID: validULID,
		Kind:  notifyv2.KindNeedsInput,
		Host:  "rig-1",
		Title: "needs input",
		Actions: []notifyv2.Action{
			{ID: "approve", Label: "Approve", URL: "https://example.ts.net/approve/ablk_ok_xxx"},
		},
	}
	note := notifyv2.Render(m, notifyv2.RenderOpts{})
	assert.Nil(t, note.Actions, "non-approval kinds must have nil Actions even if Message.Actions is populated")
}

// kindTitles is the canonical safe verb phrase per kind, mirroring what
// consumers send on the wire. Used by the BACK-08 zero-network render suite.
var kindTitles = map[notifyv2.Kind]string{
	notifyv2.KindNeedsInput:      "needs input",
	notifyv2.KindCommandDone:     "done ✓",
	notifyv2.KindApprovalRequest: "approval required",
	notifyv2.KindWatchFired:      "watch fired",
	notifyv2.KindAgentStopped:    "agent stopped",
}

// TestRenderTitle_NonEmptyForEveryKind is the BACK-08 zero-network render
// suite: for EVERY kind, a minimal VALID message renders a non-empty title.
// Render is pure code — no I/O, no network — so this is exactly what the
// phone shows when it is off the tailnet at fetch time.
func TestRenderTitle_NonEmptyForEveryKind(t *testing.T) {
	for kind, title := range kindTitles {
		t.Run(string(kind), func(t *testing.T) {
			m := notifyv2.Message{
				V:     2,
				MsgID: validULID,
				Kind:  kind,
				Title: title,
			}
			require.NoError(t, m.Validate(), "the minimal message must be valid")
			note := notifyv2.Render(m, notifyv2.RenderOpts{})
			assert.NotEmpty(t, strings.TrimSpace(note.Title),
				"BACK-08: rendered title must never be empty")
		})
	}
}

// TestRenderTitle_EmptyCompositionFallback asserts the BACK-08 floor: when
// title composition yields nothing (defense in depth — Validate rejects an
// empty Title upstream, but Render must not rely on that), the fixed
// fallback renders instead of an empty notification.
func TestRenderTitle_EmptyCompositionFallback(t *testing.T) {
	cases := []struct {
		name string
		msg  notifyv2.Message
	}{
		{name: "zero message", msg: notifyv2.Message{}},
		{name: "kind only", msg: notifyv2.Message{V: 2, Kind: notifyv2.KindNeedsInput}},
		{name: "blank title", msg: notifyv2.Message{V: 2, Kind: notifyv2.KindNeedsInput, Title: "   "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			note := notifyv2.Render(tc.msg, notifyv2.RenderOpts{})
			assert.Equal(t, "abysslink: attention needed", note.Title,
				"empty composition must render the fixed fallback title")
		})
	}

	// A message with host but no verb phrase still renders non-empty (and
	// without a dangling separator).
	note := notifyv2.Render(notifyv2.Message{V: 2, Kind: notifyv2.KindNeedsInput, Host: "rig-1"}, notifyv2.RenderOpts{})
	assert.Equal(t, "rig-1", note.Title)
	assert.NotContains(t, note.Title, "·")
}
