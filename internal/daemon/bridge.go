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
	"log/slog"

	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/session"
)

// ConsumeTransitions is the registry→dispatch bridge (BACK-03/BACK-04): it
// ranges the registry's Events channel and turns each session.Transition into
// a validated v2 Message dispatched at HEURISTIC origin — so the D-08
// cooldown applies (explicit POSTs bypass it; this path must not). It returns
// when ctx is cancelled or the events channel closes.
//
// Messages are built EXCLUSIVELY from Transition metadata fields (IDs, epoch,
// consumer, kind) — pane content structurally never reaches this function,
// and every Message still passes the dispatcher's Validate gate (secret scan
// included) before egress (T-27-28). Display names ride RenderOpts so the
// rendered body carries the D-19 breadcrumb without entering the wire schema.
//
// Per-transition errors (validation, delivery policy) are logged and the loop
// continues — one bad transition never stops the bridge.
func (s *Server) ConsumeTransitions(ctx context.Context, events <-chan session.Transition) {
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-events:
			if !ok {
				return
			}
			s.bridgeTransition(ctx, t)
		}
	}
}

// bridgeTransition maps one Transition into a dispatched v2 Message.
// Kind/title mapping (plan 27-07):
//   - TransitionNeedsInput  → needs_input, "needs input"
//   - TransitionRestartLost → agent_stopped,
//     "lost at tmux restart (was waiting for input)" (D-29)
//   - TransitionCleared     → state only, no notification (visibility lives
//     on GET /sessions)
func (s *Server) bridgeTransition(ctx context.Context, t session.Transition) {
	var kind notifyv2.Kind
	var title string
	switch t.Type {
	case session.TransitionNeedsInput:
		kind, title = notifyv2.KindNeedsInput, "needs input"
	case session.TransitionRestartLost:
		kind, title = notifyv2.KindAgentStopped, "lost at tmux restart (was waiting for input)"
	case session.TransitionCleared:
		return // edge consumed; /sessions shows the cleared state
	default:
		slog.Debug("daemon: unknown transition type skipped", "type", int(t.Type))
		return
	}

	msg := notifyv2.Message{
		V:     2,
		MsgID: notifyv2.NewMsgID(),
		Kind:  kind,
		Host:  s.hostname,
		Session: notifyv2.SessionRef{
			Session: t.SessionID,
			Window:  t.WindowID,
			Pane:    t.PaneID,
			Epoch:   t.Epoch,
		},
		Consumer: t.Consumer,
		Title:    title,
	}

	// Content-store minting (BACK-06) deliberately does NOT happen here:
	// heuristic transitions carry no body today (Transition is metadata-only
	// by construction — pane content structurally never reaches the bridge).
	// If a future phase wants the wake to carry a pane excerpt, it must mint
	// via Server.mintFetchRef AND re-run the secret scan on the excerpt;
	// until then the fallback title is the whole payload (BACK-08).
	opts := notifyv2.RenderOpts{SessionName: t.SessionName, WindowName: t.WindowName}
	if err := s.dispatch.dispatch(ctx, msg, originHeuristic, opts); err != nil {
		// NET-11 voice: log and continue — the bridge survives any single bad
		// transition. Metadata only in the log line.
		slog.Warn("daemon: transition dispatch rejected",
			"err", err, "pane", t.PaneID, "epoch", t.Epoch, "kind", kind)
	}
}
