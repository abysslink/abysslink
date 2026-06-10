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
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// eventKind classifies one control-mode protocol line.
type eventKind int

const (
	// eventSkip is an unrecognized line outside a block — skipped with a
	// debug log, never an error (RESEARCH Pitfall 4: tmux output must
	// never take the parser down).
	eventSkip eventKind = iota
	// eventBlockBegin is a %begin line: a command-reply block starts.
	eventBlockBegin
	// eventBlockEnd is a %end line: the reply block ends successfully.
	eventBlockEnd
	// eventBlockError is a %error line: the reply block ends with an error.
	eventBlockError
	// eventReply is any line inside a %begin/%end block (reply payload).
	eventReply
	// eventNotification is an out-of-band %-notification outside a block.
	eventNotification
)

// event is the classification of one fed line. name/rest are populated for
// notifications; rest carries the payload for reply lines.
type event struct {
	kind eventKind
	name string // notification name including the leading '%'
	rest string // remainder after the name (notification args / reply text)
}

// notifExit is the notification tmux emits when the control client is
// exiting (server death, detach, no sessions) — the stream then EOFs and the
// supervisor re-attaches with an epoch bump.
const notifExit = "%exit"

// structuralNotifications are the control-mode notifications that signal a
// structural change in the session/window/pane tree. They only ever trigger
// a debounced list-panes re-poll — never a direct state mutation (events
// trigger polls; polls write state). Unknown notification names are skipped:
// tmux adds notifications across versions.
//
//nolint:gochecknoglobals // gochecknoglobals: immutable lookup table
var structuralNotifications = map[string]bool{
	"%sessions-changed":        true,
	"%session-changed":         true,
	"%session-renamed":         true,
	"%window-add":              true,
	"%window-close":            true,
	"%window-renamed":          true,
	"%unlinked-window-add":     true,
	"%unlinked-window-close":   true,
	"%unlinked-window-renamed": true,
	"%layout-change":           true,
	"%client-detached":         true,
	"%client-session-changed":  true,
}

// parser is the tmux control-mode line state machine (RESEARCH Pattern 4).
// Command replies are bracketed %begin…%end/%error; notifications arrive
// only between blocks. The zero value is ready to use.
type parser struct {
	inBlock bool
}

// feed classifies one protocol line and advances the block state. It never
// errors: anything unrecognized is a skip event with a debug log (Pitfall 4).
func (p *parser) feed(line string) event {
	name, rest, _ := strings.Cut(line, " ")
	if p.inBlock {
		switch name {
		case "%end":
			p.inBlock = false
			return event{kind: eventBlockEnd, rest: rest}
		case "%error":
			p.inBlock = false
			return event{kind: eventBlockError, rest: rest}
		default:
			// Everything inside a block is reply payload — even
			// %-prefixed lines (notifications never occur in-block).
			return event{kind: eventReply, rest: line}
		}
	}
	switch {
	case name == "%begin":
		p.inBlock = true
		return event{kind: eventBlockBegin, rest: rest}
	case strings.HasPrefix(name, "%"):
		return event{kind: eventNotification, name: name, rest: rest}
	default:
		slog.Debug("session: unknown control-mode line skipped", "line_prefix", name)
		return event{kind: eventSkip}
	}
}

// parseTmuxVersion parses `tmux -V` output ("tmux 3.3a") into (3, 3).
// Mirrors internal/modules/tmux.parseTmuxVersion — duplicated with
// attribution because the session package must not import internal/modules
// (the registry sits below the module layer).
func parseTmuxVersion(output string) (int, int, error) {
	parts := strings.Fields(output)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unexpected format: %q", output)
	}
	versionStr := parts[1]
	// tmux master builds report "tmux next-3.4": strip the prefix so a
	// development build of a >= 3.2 tmux passes the version gate instead of
	// degrading on a parse failure.
	versionStr = strings.TrimPrefix(versionStr, "next-")
	// Strip trailing non-numeric suffix (e.g. "3.3a" → "3.3").
	for len(versionStr) > 0 && (versionStr[len(versionStr)-1] < '0' || versionStr[len(versionStr)-1] > '9') {
		versionStr = versionStr[:len(versionStr)-1]
	}
	dotParts := strings.SplitN(versionStr, ".", 2)
	if len(dotParts) < 2 {
		return 0, 0, fmt.Errorf("no dot in version %q", versionStr)
	}
	major, err := strconv.Atoi(dotParts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("parse major: %w", err)
	}
	minor, err := strconv.Atoi(dotParts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parse minor: %w", err)
	}
	return major, minor, nil
}
