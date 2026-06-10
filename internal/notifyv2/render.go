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

// RenderedNote is the string output of Render: everything the ntfy delivery
// path (internal/modules/notify) needs to compose a request. Header names
// live in the delivery module — this package produces strings only.
//
// There is deliberately no actions field: Message.Actions are typed and
// validated on the wire but dropped by this renderer until Phase 30 wires
// /approve (D-18 — no dead buttons).
type RenderedNote struct {
	Title    string
	Body     string
	Priority string
	Tags     string
	Click    string
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
// Message.Actions are deliberately not rendered (D-18): typed and validated
// on the wire today, surfaced as buttons only when Phase 30 wires /approve.
func Render(m Message, opts RenderOpts) RenderedNote {
	return RenderedNote{
		Title:    renderTitle(m),
		Body:     renderBody(m, opts),
		Priority: priorityFor(m),
		Tags:     kindTags[m.Kind],
		Click:    opts.Click, // D-16: verbatim passthrough; empty stays empty
	}
}

// renderTitle composes the locked compact title form, joining non-empty
// segments with " · ": host, display consumer, then pane ID + verb phrase
// (e.g. "rig-1 · claude · %3 needs input"). With no session identity the
// title degrades to "rig-1 · needs input" — never a bare verb phrase.
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
		last = m.Session.Pane + " " + m.Title
	}
	segs = append(segs, last)
	return strings.Join(segs, titleSep)
}

// renderBody composes a few short lines of routing metadata only (D-19): a
// display-name breadcrumb when the caller resolved names, then kind, host,
// and raw IDs+epoch lines. Message has no body/content field, and the fields
// rendered here are shape-pinned by Validate (Host to a hostname shape, IDs
// to tmux literal forms) so pane content cannot reach this function through a
// validated message. Callers must Validate before Render.
func renderBody(m Message, opts RenderOpts) string {
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
