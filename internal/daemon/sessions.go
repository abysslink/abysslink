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
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/abysslink/abysslink/internal/session"
)

// statusRegistryDisabled is the /sessions status string when no registry was
// wired via SetSessionRegistry (session_registry.enabled false, or a build
// without the registry) — honest like the registry's own degraded states.
const statusRegistryDisabled = "registry: disabled"

// sessionsResponse is the JSON schema for GET /sessions (BACK-04). Status is
// the registry's verbatim health string ("ok", "tmux: unavailable",
// "tmux: unsupported (X.Y, need >= 3.2)", or "registry: disabled") — degraded
// states surface as honest strings with an empty sessions list, never a 5xx
// and never fabricated data (D-26/D-27).
type sessionsResponse struct {
	Status      string        `json:"status"`
	Epoch       uint64        `json:"epoch"`
	TmuxVersion string        `json:"tmux_version,omitempty"`
	Sessions    []sessionJSON `json:"sessions"`
}

// sessionJSON is one tmux session in the /sessions tree. IDs route, names
// display — both included verbatim from the registry snapshot.
type sessionJSON struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Attached int          `json:"attached"`
	Windows  []windowJSON `json:"windows"`
}

// windowJSON is one tmux window in the /sessions tree.
type windowJSON struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Panes []paneJSON `json:"panes"`
}

// paneJSON is one tmux pane in the /sessions tree. needs_input_since is
// RFC3339 and present only while needs_input; suppressed_count/cooldown_until
// are the D-15 dispatcher suppression stats, present only when active.
type paneJSON struct {
	ID              string `json:"id"`
	Active          bool   `json:"active"`
	AlternateScreen bool   `json:"alternate_screen"`
	Consumer        string `json:"consumer"`
	NeedsInput      bool   `json:"needs_input"`
	NeedsInputSince string `json:"needs_input_since,omitempty"`
	SuppressedCount int    `json:"suppressed_count,omitempty"`
	CooldownUntil   string `json:"cooldown_until,omitempty"`
}

// handleSessions serves GET /sessions: a read-only JSON view of the live tmux
// session registry (sessions/windows/panes with needs_input state, the
// registry epoch, and D-15 suppression stats). Like /status, this route is
// served ONLY over the local unix socket (chmod 0600, see Run), which is the
// local-only trust boundary — it is NOT a tailnet/TCP endpoint and carries no
// WhoIs/TLS of its own. The response carries session topology METADATA only
// (IDs, display names, flags, timestamps) — never pane content (T-27-27).
// This route MUST NOT be moved onto a network listener without first routing
// it through the webui's WhoIs gate (WR-04).
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := s.buildSessionsResponse()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("daemon: sessions encode failed", "err", err)
	}
}

// buildSessionsResponse maps the registry snapshot into the /sessions JSON
// shape. A nil sessionSource (no SetSessionRegistry call) yields the honest
// "registry: disabled" status with an empty list — the same fail-honest
// stance as the registry's own degraded statuses (T-27-30).
func (s *Server) buildSessionsResponse() sessionsResponse {
	// Sessions is always a non-nil slice so the JSON field is [] (never null)
	// in every state including degraded.
	resp := sessionsResponse{Sessions: []sessionJSON{}}
	if s.sessionSource == nil {
		resp.Status = statusRegistryDisabled
		return resp
	}

	snap := s.sessionSource.Snapshot()
	resp.Status = snap.Status
	resp.Epoch = snap.Epoch
	resp.TmuxVersion = snap.TmuxVersion
	for _, sess := range snap.Sessions {
		sj := sessionJSON{
			ID:       sess.ID,
			Name:     sess.Name,
			Attached: sess.Attached,
			Windows:  []windowJSON{},
		}
		for _, win := range sess.Windows {
			wj := windowJSON{ID: win.ID, Name: win.Name, Panes: []paneJSON{}}
			for _, p := range win.Panes {
				wj.Panes = append(wj.Panes, s.paneJSONFrom(snap.Epoch, p))
			}
			sj.Windows = append(sj.Windows, wj)
		}
		resp.Sessions = append(resp.Sessions, sj)
	}
	return resp
}

// paneJSONFrom maps one snapshot pane, merging the dispatcher's D-15
// suppression stats for (epoch, pane): suppressed_count and cooldown_until
// appear only when active (non-zero) — omitempty drops them otherwise.
func (s *Server) paneJSONFrom(epoch uint64, p session.PaneState) paneJSON {
	pj := paneJSON{
		ID:              p.ID,
		Active:          p.Active,
		AlternateScreen: p.AlternateOn,
		Consumer:        p.Consumer,
		NeedsInput:      p.NeedsInput,
	}
	if p.NeedsInput && !p.NeedsInputSince.IsZero() {
		pj.NeedsInputSince = p.NeedsInputSince.Format(time.RFC3339)
	}
	suppressed, until := s.dispatch.paneStats(epoch, p.ID)
	if suppressed > 0 {
		pj.SuppressedCount = suppressed
	}
	if !until.IsZero() {
		pj.CooldownUntil = until.Format(time.RFC3339)
	}
	return pj
}
