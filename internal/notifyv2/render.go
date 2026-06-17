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

package notifyv2

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// RenderedAction carries one ntfy action button. The URL is a 256-bit
// single-use capability token — never log it, never persist it. Phase 30
// populates this for KindApprovalRequest messages (D-18 un-dropped).
type RenderedAction struct {
	Label string // "Approve" or "Deny"
	URL   string // single-use capability URL — NEVER logged
}

// RenderedNote is the string output of Render: everything the ntfy delivery
// path (internal/modules/notify) needs to compose a request. Header names
// live in the delivery module — this package produces strings only.
type RenderedNote struct {
	Title    string
	Body     string
	Priority string
	Tags     string
	Click    string
	Actions  []RenderedAction // nil unless KindApprovalRequest with populated Actions[]
}

// RenderOpts carries display-only enrichment the caller resolved out-of-band
// (session/window display names from the registry, click URL from dispatch).
type RenderOpts struct {
	SessionName string
	WindowName  string
	Click       string
}

// consumerDisplay maps canonical wire consumer IDs to display names (D-24:
// the wire carries canonical IDs, the renderer owns display). The D-23 shell
// normalization is repeated here as defense in depth — the registry
// normalizes before building messages, but explicit POST callers may send
// raw values. Anything not in the map renders verbatim.
var consumerDisplay = map[string]string{
	"claudecode": "claude",
	"zsh":        "shell",
	"bash":       "shell",
	"fish":       "shell",
	"sh":         "shell",
}

// kindTags is the fixed kind→ntfy emoji shortcode map (D-21). Shortcode
// names verified against docs.ntfy.sh/emojis on 2026-06-10 (research
// assumption A2): the 🛑 shortcode there is "stop_sign", not
// "octagonal_sign". A wrong name would render as a plain-text tag.
var kindTags = map[Kind]string{
	KindNeedsInput:      "question",             // ❓
	KindCommandDone:     "white_check_mark",     // ✅
	KindApprovalRequest: "closed_lock_with_key", // 🔐
	KindWatchFired:      "eyes",                 // 👀
	KindAgentStopped:    "stop_sign",            // 🛑
}

// maxDisplayRunes caps session/window display names in the body so long or
// multibyte names cannot bloat the note (Pitfall 7 — truncation is rune-safe,
// never byte-slicing).
const maxDisplayRunes = 32

// Title/breadcrumb separators: middle dot (U+00B7) for the compact title,
// single right-pointing angle quotation mark (U+203A) for the body
// breadcrumb (D-19).
const (
	titleSep = " · "
	crumbSep = " › "
)

// Render produces the ntfy representation of m. Pure function: no I/O, no
// logging, no mutation.
//
// For KindApprovalRequest messages with populated Actions[], the returned
// RenderedNote.Actions carries one RenderedAction per action button. The ntfy
// delivery module translates these to X-Actions: headers (D-18 un-dropped,
// Phase 30).
func Render(m Message, opts RenderOpts) RenderedNote {
	note := RenderedNote{
		Title:    renderTitle(m),
		Body:     renderBody(m, opts),
		Priority: priorityFor(m),
		Tags:     kindTags[m.Kind],
		Click:    opts.Click, // D-16: verbatim passthrough; empty stays empty
	}
	if m.Kind == KindApprovalRequest && len(m.Actions) > 0 {
		note.Actions = renderActions(m.Actions)
	}
	return note
}

// renderActions maps Message.Actions to []RenderedAction for the ntfy
// X-Actions: header. Only actions with a non-empty URL are included — an
// action without a URL cannot produce a working button (D-18).
func renderActions(actions []Action) []RenderedAction {
	out := make([]RenderedAction, 0, len(actions))
	for _, a := range actions {
		if a.URL == "" {
			continue // no capability URL yet — omit the button (D-18 no dead buttons)
		}
		out = append(out, RenderedAction{Label: a.Label, URL: a.URL})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fallbackTitle is the BACK-08 guarantee: a push wake must NEVER render an
// empty title. Rendering is pure code (zero network access), so when title
// composition yields nothing the phone still shows something actionable —
// even off-tailnet at fetch time, where the body fetch would fail.
const fallbackTitle = "abysslink: attention needed"

// renderTitle composes the locked compact title form, joining non-empty
// segments with " · ": host, display consumer, then pane ID + verb phrase
// (e.g. "rig-1 · claude · %3 needs input"). With no session identity the
// title degrades to "rig-1 · needs input" — never a bare verb phrase.
//
// BACK-08: the result is never empty. Validate rejects an empty Message.Title
// upstream, but renderTitle is pure defense in depth — if composition still
// yields an empty/blank string (e.g. an unvalidated message), the fixed
// fallbackTitle is returned instead.
func renderTitle(m Message) string {
	var segs []string
	if m.Host != "" {
		segs = append(segs, m.Host)
	}
	if dc := displayConsumer(m.Consumer); dc != "" {
		segs = append(segs, dc)
	}
	last := m.Title
	if m.Session.Pane != "" {
		last = strings.TrimSpace(m.Session.Pane + " " + m.Title)
	}
	if last != "" {
		segs = append(segs, last)
	}
	title := strings.Join(segs, titleSep)
	if strings.TrimSpace(title) == "" {
		return fallbackTitle
	}
	return title
}

// renderBody composes a few short lines of routing metadata only (D-19): a
// display-name breadcrumb when the caller resolved names, then kind, host,
// and raw IDs+epoch lines. Message has no body/content field, and the fields
// rendered here are shape-pinned by Validate (Host to a hostname shape, IDs
// to tmux literal forms) so pane content cannot reach this function through a
// validated message. Callers must Validate before Render.
func renderBody(m Message, opts RenderOpts) string {
	// KindApprovalRequest gets a clean, human-facing body for the phone approval
	// card — not the developer "kind:/host:/ids:" dump. The actionable choice is
	// the Approve/Deny buttons; the body never includes those literal words (the
	// anti-leak guard TestRender_ActionsDropped_NoURL asserts button text never
	// bleeds into the text fields).
	if m.Kind == KindApprovalRequest {
		if h := strings.TrimSpace(m.Host); h != "" {
			return "Permission requested on " + h + ". Respond from your phone."
		}
		return "Permission requested. Respond from your phone."
	}

	var lines []string

	var crumb []string
	if s := truncateRunes(opts.SessionName, maxDisplayRunes); s != "" {
		crumb = append(crumb, s)
	}
	if w := truncateRunes(opts.WindowName, maxDisplayRunes); w != "" {
		crumb = append(crumb, w)
	}
	if len(crumb) > 0 {
		if m.Session.Pane != "" {
			crumb = append(crumb, m.Session.Pane)
		}
		lines = append(lines, strings.Join(crumb, crumbSep))
	}

	lines = append(lines, "kind: "+string(m.Kind), "host: "+m.Host)

	if m.Session != (SessionRef{}) {
		var ids []string
		for _, id := range []string{m.Session.Session, m.Session.Window, m.Session.Pane} {
			if id != "" {
				ids = append(ids, id)
			}
		}
		lines = append(lines, fmt.Sprintf("ids: %s epoch %d", strings.Join(ids, " "), m.Session.Epoch))
	}

	return strings.Join(lines, "\n")
}

// priorityFor maps wire priority to the ntfy 1-5 numeric scale (D-14):
// approval_request is always urgent (5) regardless of the wire field;
// "high" maps to 4; everything else is the default 3.
func priorityFor(m Message) string {
	if m.Kind == KindApprovalRequest {
		return "5"
	}
	if m.Priority == "high" {
		return "4"
	}
	return "3"
}

// displayConsumer applies the renderer-owned display map; unknown consumers
// render verbatim, empty stays empty (segment omitted by the caller).
func displayConsumer(consumer string) string {
	if d, ok := consumerDisplay[consumer]; ok {
		return d
	}
	return consumer
}

// truncateRunes shortens s to at most n runes, never byte-slicing a rune
// (Pitfall 7: display names can be CJK/emoji).
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
