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
	"crypto/rand"

	"github.com/oklog/ulid/v2"
)

// Kind classifies a v2 notification. The set is closed: Validate() rejects
// anything outside the five enum values below.
type Kind string

// The five v2 notification kinds (SPEC §4.2).
const (
	// KindNeedsInput means a session is waiting on the human.
	KindNeedsInput Kind = "needs_input"
	// KindCommandDone means a wrapped command finished (exit detail arrives
	// via the Phase 28 fetched body, never in the payload).
	KindCommandDone Kind = "command_done"
	// KindApprovalRequest means a blocked action needs approve/deny.
	KindApprovalRequest Kind = "approval_request"
	// KindWatchFired means a declarative watcher tripped.
	KindWatchFired Kind = "watch_fired"
	// KindAgentStopped means an agent turn ended or the kill-switch fired.
	KindAgentStopped Kind = "agent_stopped"
)

// Message is the v2 notification wire schema (SPEC §4.1). It carries routing
// metadata only — there is deliberately no body/content field; content lives
// behind Fetch.URLTailnet. Title is the safe generic verb phrase (e.g.
// "needs input", "done ✓"); the renderer composes the full compact title.
type Message struct {
	V        int        `json:"v"`
	MsgID    string     `json:"msg_id"`
	Kind     Kind       `json:"kind"`
	Host     string     `json:"host"`
	Session  SessionRef `json:"session,omitzero"`
	Consumer string     `json:"consumer,omitempty"`
	Title    string     `json:"title"`
	DeepLink string     `json:"deep_link,omitempty"`
	Fetch    *FetchRef  `json:"fetch,omitempty"`
	Priority string     `json:"priority,omitempty"`
	Actions  []Action   `json:"actions,omitempty"`
}

// SessionRef identifies the tmux session/window/pane a message routes to.
// All-empty is valid: hook and CLI consumers outside tmux have no session
// identity. Epoch distinguishes tmux server generations (bumped on restart).
type SessionRef struct {
	Session string `json:"session,omitempty"`
	Window  string `json:"window,omitempty"`
	Pane    string `json:"pane,omitempty"`
	Epoch   uint64 `json:"epoch,omitempty"`
}

// FetchRef points at the tailnet-only content store entry for a message
// (Phase 28). The URL must be https on the tailnet (Validate enforces).
type FetchRef struct {
	URLTailnet string `json:"url_tailnet"`
	TTLSeconds int    `json:"ttl_s"`
}

// Action is a typed approve/deny button. Typed and validated now; the ntfy
// renderer drops actions until Phase 30 wires /approve (D-18 — no dead
// buttons).
type Action struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

// NewMsgID returns a fresh ULID string for Message.MsgID, using explicit
// crypto/rand entropy (research A4: prefer explicit crypto entropy over
// ulid.Make's shared default). crypto/rand.Reader never returns an error on
// Go ≥ 1.24 (the runtime aborts if the OS entropy source is broken), so
// MustNew cannot panic in normal control flow.
func NewMsgID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
