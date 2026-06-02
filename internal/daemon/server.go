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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/shell"
)

// daemonVersion is the abysslinkd build version reported by GET /status. It
// defaults to "dev"; Plan 04 wires the real value from the build ldflag.
var daemonVersion = "dev"

// Watcher polling defaults. The pane watcher fires when a pane has shown a
// prompt-shaped last line with no output change for at least idleInterval.
const (
	panePollInterval = 5 * time.Second
	paneIdleInterval = 30 * time.Second
	paneCoolOff      = 5 * time.Minute
	readHeaderTO     = 5 * time.Second
)

// promptRegex matches common shell/REPL prompt-shaped trailing lines.
var promptRegex = regexp.MustCompile(`[>$?#»❯]\s*$`)

// RingAdder records a delivered notification in the Phase 19 web-UI notify-history
// ring. It is defined here (not imported from internal/modules/webui) so the
// daemon package carries zero webui/Tailscale-SDK imports and the base binary
// stays SDK-free (T-19-08); the webui ring satisfies it via a thin adapter in
// the //go:build webui daemon entrypoint (cmd/abysslinkd/start_webui.go). It
// receives only metadata (title/topic/priority/time) — never the body content
// (T-19-19 / AUD-04: no secret bodies on observable surfaces).
type RingAdder interface {
	AddEvent(title, topic, priority string, t time.Time)
}

// Server serves the notify socket and runs configured watchers.
type Server struct {
	notifier   Notifier
	runner     shell.Runner
	cfg        *config.Config
	socketPath string
	startedAt  time.Time
	ring       RingAdder // nil unless the webui build wires it via SetRing
}

// NewServer returns a Server. notifier MUST be a direct backend (see Notifier).
func NewServer(notifier Notifier, runner shell.Runner, cfg *config.Config) *Server {
	return &Server{
		notifier:   notifier,
		runner:     runner,
		cfg:        cfg,
		socketPath: SocketPath(),
		startedAt:  time.Now(),
	}
}

// SetRing injects the web-UI notify-history ring. It is called only by the
// //go:build webui daemon entrypoint; in the base build the ring stays nil and
// handleNotify skips the record (no-op, nil-safe).
func (s *Server) SetRing(r RingAdder) { s.ring = r }

// Run listens on the Unix socket and starts watchers until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("daemon: clear stale socket: %w", err)
	}
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("daemon: listen %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("daemon: chmod socket: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/notify", s.handleNotify)
	mux.HandleFunc("/status", s.handleStatus)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: readHeaderTO}

	s.startWatchers(ctx)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = os.Remove(s.socketPath)
	}()

	slog.Info("abysslinkd listening", "socket", s.socketPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("daemon: serve: %w", err)
	}
	return nil
}

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req NotifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		http.Error(w, "title is required", http.StatusBadRequest)
		return
	}
	if err := s.notifier.Send(r.Context(), req.Title, req.Body); err != nil {
		slog.Warn("daemon: notify delivery failed", "err", err)
		http.Error(w, "delivery failed", http.StatusBadGateway)
		return
	}
	// Record the delivery in the web-UI notify-history ring (Phase 19, WEB-07).
	// Metadata only — never req.Body (T-19-19). nil when webui is not wired.
	if s.ring != nil {
		s.ring.AddEvent(req.Title, req.Topic, req.Priority, time.Now())
	}
	w.WriteHeader(http.StatusNoContent)
}

// daemonStatusResponse is the JSON schema for GET /status, consumed by the
// Phase 19 Web UI. rig_id is opaque (SHA-256 prefix of the hostname) — no raw
// hostname, IP, or node_id is exposed (OBS-04).
type daemonStatusResponse struct {
	Version    string              `json:"version"`
	Backend    string              `json:"backend"`
	RigID      string              `json:"rig_id"`
	Reachable  bool                `json:"reachable"`
	LockStatus string              `json:"lock_status"`
	Doctor     daemonDoctorSummary `json:"doctor"`
	CertExpiry string              `json:"cert_expiry,omitempty"`
	LastSeen   string              `json:"last_seen,omitempty"`
	Uptime     string              `json:"uptime"`

	// PostureComplete signals whether reachable + doctor are authoritative
	// posture data. It is false this phase (OBS-07 stub): full doctor wiring is
	// deferred to Phase 19, so reachable is a hardcoded true and the doctor
	// counts are zeroed. Consumers (e.g. the Phase 19 Web UI / fleet aggregator)
	// MUST treat reachable/doctor as non-authoritative while this is false and
	// not report a fabricated "0 fatal, reachable" all-clear (WR-05).
	PostureComplete bool `json:"posture_complete"`
}

// daemonDoctorSummary is the per-severity doctor finding count in /status.
type daemonDoctorSummary struct {
	Fatal int `json:"fatal"`
	Warn  int `json:"warn"`
	Pass  int `json:"pass"`
}

// handleStatus serves GET /status: a read-only JSON posture snapshot of the
// daemon. This route is served ONLY over the local Unix socket (chmod 0600,
// see Run), which is the local-only trust boundary — it is NOT a tailnet/TCP
// endpoint and carries no WhoIs/TLS of its own. The Phase-19 web UI is a
// SEPARATE TLS+WhoIs-gated listener (internal/modules/webui) that reads the
// same posture data; it does not expose this mux. These /status, /notify, and
// /health routes MUST NOT be moved onto a network listener without first
// routing them through the webui's WhoIs gate (WR-04). Reachability is true
// because the daemon is running; full doctor wiring is deferred (OBS-07).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	backendType := "tailscale"
	hostname := ""
	lock := false
	if s.cfg != nil {
		if s.cfg.Backend.Type != "" {
			backendType = s.cfg.Backend.Type
		}
		hostname = s.cfg.Tailnet.Hostname
		lock = s.cfg.Tailnet.Lock.Enabled
	}

	lockStatus := "unlocked"
	if lock {
		lockStatus = "locked"
	}

	resp := daemonStatusResponse{
		Version:    daemonVersion,
		Backend:    backendType,
		RigID:      metrics.OpaqueRigLabel(hostname),
		Reachable:  true,                  // STUB (OBS-07): not yet wired — see PostureComplete.
		LockStatus: lockStatus,            // authoritative: read from config.
		Doctor:     daemonDoctorSummary{}, // STUB (OBS-07): zeroed counts, not a real all-clear.
		Uptime:     time.Since(s.startedAt).Truncate(time.Second).String(),
		// PostureComplete=false flags reachable/doctor as non-authoritative this
		// phase so consumers do not read the zeroed doctor summary as a genuine
		// "0 fatal" all-clear on a security-posture endpoint (WR-05).
		PostureComplete: false,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("daemon: status encode failed", "err", err)
	}
}

// startWatchers launches a goroutine per configured watcher (pane, file, HTTP).
func (s *Server) startWatchers(ctx context.Context) {
	if s.cfg == nil || !s.cfg.Modules.Watch.Enabled {
		return
	}
	for _, pane := range s.cfg.Modules.Watch.Panes {
		go s.watchPane(ctx, pane)
	}
	s.startFileAndHTTPWatchers(ctx)
}

// panePoll returns the pane watcher poll interval, using YAML config if set.
func (s *Server) panePoll() time.Duration {
	if s.cfg != nil && s.cfg.Modules.Watch.PanePollSecs > 0 {
		return time.Duration(s.cfg.Modules.Watch.PanePollSecs) * time.Second
	}
	return panePollInterval
}

// paneIdle returns the idle threshold before a notification fires.
func (s *Server) paneIdle() time.Duration {
	if s.cfg != nil && s.cfg.Modules.Watch.PaneIdleSecs > 0 {
		return time.Duration(s.cfg.Modules.Watch.PaneIdleSecs) * time.Second
	}
	return paneIdleInterval
}

// paneCoolOffDur returns the cool-off between successive pane notifications.
func (s *Server) paneCoolOffDur() time.Duration {
	if s.cfg != nil && s.cfg.Modules.Watch.PaneCoolOffSecs > 0 {
		return time.Duration(s.cfg.Modules.Watch.PaneCoolOffSecs) * time.Second
	}
	return paneCoolOff
}

// watchPane polls a tmux pane and notifies when it has been idle at a prompt.
func (s *Server) watchPane(ctx context.Context, pane string) {
	ticker := time.NewTicker(s.panePoll())
	defer ticker.Stop()

	var lastHash string
	var idleSince, lastNotified time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		res, err := s.runner.Run(ctx, "tmux", "capture-pane", "-t", pane, "-p")
		if err != nil || res.ExitCode != 0 {
			continue
		}
		sum := fmt.Sprintf("%x", sha256.Sum256([]byte(res.Stdout)))
		now := time.Now()
		if sum != lastHash {
			lastHash = sum
			idleSince = now
			continue
		}
		if now.Sub(idleSince) < s.paneIdle() || now.Sub(lastNotified) < s.paneCoolOffDur() {
			continue
		}
		if !promptRegex.MatchString(lastNonEmptyLine(res.Stdout)) {
			continue
		}
		if err := s.notifier.Send(ctx, "waiting for input", fmt.Sprintf("tmux pane %q is idle at a prompt", pane)); err != nil {
			slog.Warn("daemon: pane watcher notify failed", "pane", pane, "err", err)
			continue
		}
		lastNotified = now
	}
}

// lastNonEmptyLine returns the last non-blank line of s.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}
