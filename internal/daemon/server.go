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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/shell"
)

// daemonVersion is the abysslinkd build version reported by GET /status. It
// defaults to "dev"; Plan 04 wires the real value from the build ldflag.
var daemonVersion = "dev"

// maxNotifyBody caps the /notify request body. ntfy title ≤ 250 chars,
// message ≤ 4096 chars; 256 KiB is ~60x the largest legit ntfy payload (A11 / DOS-01).
const maxNotifyBody = 256 * 1024 // 256 KiB

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
	// execCount reads the gate decorator's atomic exec counter (D-38). nil
	// unless the composition root wires it via SetExecCounter; handleStatus
	// reports 0 when unset (nil-safe).
	execCount func() uint64
	// dispatch is the v2 policy engine (cooldown, flood ceiling, retry —
	// plan 27-05); its retry loop is started by Run.
	dispatch *dispatcher
	// hostname is the cached short hostname used to enrich v2 messages with
	// an empty host field (computed once at NewServer).
	hostname string
}

// NewServer returns a Server. notifier MUST be a direct backend (see Notifier).
func NewServer(notifier Notifier, runner shell.Runner, cfg *config.Config) *Server {
	return &Server{
		notifier:   notifier,
		runner:     runner,
		cfg:        cfg,
		socketPath: SocketPath(),
		startedAt:  time.Now(),
		dispatch:   newDispatcher(notifier, cfg),
		hostname:   shortHostname(),
	}
}

// SetRing injects the web-UI notify-history ring. It is called only by the
// //go:build webui daemon entrypoint; in the base build the ring stays nil and
// handleNotify skips the record (no-op, nil-safe).
func (s *Server) SetRing(r RingAdder) { s.ring = r }

// SetExecCounter injects the gate decorator's exec-counter accessor
// (gate.Gated.Count) so GET /status can report gate_execs_observed — live
// proof that the observe-only seam intercepts every module/consumer exec
// (D-38). Called by the composition root before Run; nil-safe: when unset,
// handleStatus reports 0.
func (s *Server) SetExecCounter(fn func() uint64) { s.execCount = fn }

// Run listens on the Unix socket and starts watchers until ctx is cancelled.
// On cancellation it waits for the graceful shutdown (connection drain +
// socket-file removal) to complete before returning (NET-14) so the process
// cannot exit mid-drain or leave a stale socket file behind.
func (s *Server) Run(ctx context.Context) error {
	if s.socketPath == "" {
		// SocketPath failed closed (NET-13: socket dir verification failed).
		return fmt.Errorf("daemon: no usable socket path (socket directory verification failed — see prior log)")
	}
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
	// v2 dispatch retry loop (D-28); exits on ctx cancellation.
	go s.dispatch.run(ctx)

	// Graceful-shutdown goroutine: by the time srv.Shutdown runs, ctx is
	// already Done, so the drain needs a context detached from that
	// cancellation (WithoutCancel keeps ctx values) plus its own timeout.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = os.Remove(s.socketPath)
	}()

	slog.Info("abysslinkd listening", "socket", s.socketPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("daemon: serve: %w", err)
	}
	// Serve returned ErrServerClosed, which only srv.Shutdown (in the goroutine
	// above) can trigger. Wait for the drain and socket-file removal to finish
	// before returning so the caller cannot exit mid-shutdown (NET-14).
	<-shutdownDone
	return nil
}

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// A11 / DOS-01: cap the request body before decoding to prevent memory-exhaustion
	// from a hostile or compromised tailnet peer flooding POST /notify.
	r.Body = http.MaxBytesReader(w, r.Body, maxNotifyBody)
	// Read once (RESEARCH Pattern 5), probe the "v" field, branch. The cap
	// error now surfaces at ReadAll instead of Decode — same disambiguation.
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesReader sets an internal flag that causes ResponseWriter to emit 413
		// if we call http.Error after the read limit is exceeded; we disambiguate
		// here to return 413 explicitly for clarity.
		if strings.Contains(err.Error(), "request body too large") {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	var probe struct {
		V int `json:"v"`
	}
	// A probe failure on malformed JSON is fine: probe.V stays 0 and the v1
	// unmarshal below reports the identical "invalid JSON" 400.
	_ = json.Unmarshal(raw, &probe)
	if probe.V == 2 {
		s.handleNotifyV2(w, r, raw)
		return
	}

	// v1 path — byte-identical behavior (v1 NotifyRequest has no v field, so
	// probe.V == 0 routes every existing consumer here unchanged).
	var req NotifyRequest
	if err := json.Unmarshal(raw, &req); err != nil {
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

// handleNotifyV2 is the POST /notify v2 branch (BACK-05): strict decode
// (DisallowUnknownFields — the D-17 decode gate: Message has no body field,
// so any body/content-shaped key is unknown by construction), server-side
// enrichment, Validate, then dispatch through the policy engine. Explicit
// POSTs bypass the heuristic cooldown by origin (D-10). Display-name
// enrichment from the registry arrives with the bridge in plan 27-07.
func (s *Server) handleNotifyV2(w http.ResponseWriter, r *http.Request, raw []byte) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var msg notifyv2.Message
	if err := dec.Decode(&msg); err != nil {
		http.Error(w, "invalid v2 payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Enrichment before validation: hook/CLI consumers may omit msg_id and
	// host; the daemon fills both server-side.
	if msg.MsgID == "" {
		msg.MsgID = notifyv2.NewMsgID()
	}
	if msg.Host == "" {
		msg.Host = s.hostname
	}

	if err := msg.Validate(); err != nil {
		slog.Warn("daemon: v2 notify rejected", "reason", err)
		http.Error(w, "invalid v2 message: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if err := s.dispatch.dispatch(r.Context(), msg, originExplicit, notifyv2.RenderOpts{}); err != nil {
		slog.Warn("daemon: v2 dispatch rejected", "reason", err)
		http.Error(w, "invalid v2 message: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// Mirror the v1 ring-adder with METADATA ONLY (T-19-19): msg_id, kind,
	// pane — never anything body-like (the schema has no body field anyway).
	if s.ring != nil {
		parts := []string{string(msg.Kind)}
		if msg.Session.Pane != "" {
			parts = append(parts, msg.Session.Pane)
		}
		parts = append(parts, msg.MsgID)
		s.ring.AddEvent(strings.Join(parts, " "), "", msg.Priority, time.Now())
	}
	// Success response mirrors the v1 handler exactly: 204 No Content.
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

	// GateExecsObserved is live: it reads the gate decorator's atomic counter
	// via SetExecCounter — the count of module/consumer execs the observe-only
	// GatedRunner has intercepted (D-38); 0 when no gate is wired.
	GateExecsObserved uint64 `json:"gate_execs_observed"`

	// PostureComplete signals whether the DOCTOR summary is authoritative
	// posture data. It is false this phase: the full doctor families live in
	// internal/cli (a daemon→cli import would form a cycle, so the daemon cannot
	// run them), hence the doctor counts here are zeroed. Reachable is NO LONGER
	// a stub — it is a live, best-effort probe (s.resolveReachable, fail-honest
	// to false on any error/panic, never a fabricated true), so it is the only
	// authoritative live field on this response. The Web UI reads the real doctor
	// posture from cli.CollectDoctorFindings, not this endpoint. Consumers MUST
	// NOT read the zeroed doctor summary as a "0 fatal" all-clear (WR-05).
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

	// Reachability is now REAL (B3): resolve the node's own tailnet IP via the
	// backend. A daemon whose backend reports a tailnet IP is reachable on the
	// tailnet; a resolution failure is reported as not-reachable rather than a
	// hardcoded true (WR-05: never a fabricated all-clear). The doctor summary
	// remains a non-authoritative stub here — the full doctor families live in
	// internal/cli (which cannot be imported from daemon: it would form an import
	// cycle). The Web UI dashboard reads the authoritative doctor posture
	// directly from internal/cli.CollectDoctorFindings, not from this endpoint;
	// PostureComplete therefore stays false so consumers do not read the zeroed
	// doctor summary as a genuine "0 fatal" all-clear.
	reachable := s.resolveReachable(r.Context())

	// Gate exec counter (D-38): live when the composition root wired
	// SetExecCounter; 0 when no gate is present (nil-safe, never an error).
	var gateExecs uint64
	if s.execCount != nil {
		gateExecs = s.execCount()
	}

	resp := daemonStatusResponse{
		Version:    daemonVersion,
		Backend:    backendType,
		RigID:      metrics.OpaqueRigLabel(hostname),
		Reachable:  reachable,             // REAL: backend tailnet-IP resolution (B3).
		LockStatus: lockStatus,            // authoritative: read from config.
		Doctor:     daemonDoctorSummary{}, // STUB (OBS-07): zeroed counts, not a real all-clear.
		Uptime:     time.Since(s.startedAt).Truncate(time.Second).String(),
		// LIVE: the gate decorator's atomic exec counter via SetExecCounter (D-38).
		GateExecsObserved: gateExecs,
		// PostureComplete=false flags the DOCTOR summary as non-authoritative so
		// consumers do not read the zeroed doctor summary as a genuine "0 fatal"
		// all-clear on a security-posture endpoint (WR-05). Reachable is now real.
		PostureComplete: false,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("daemon: status encode failed", "err", err)
	}
}

// resolveReachable reports whether this node is reachable on the tailnet by
// resolving its own tailnet IP via the backend. A backend construction or
// IP-resolution failure (or an empty IP) yields false — an HONEST "not
// confirmed reachable" rather than the previous hardcoded true (WR-05). It
// respects ctx cancellation and never propagates a panic: the backend's
// localapi probe can panic when tailscaled is absent (e.g. CI or a
// not-yet-started daemon), which a /status handler must never surface as a 500.
// A recovered panic is treated as not-reachable (fail-honest, never a fabricated
// true) and logged via slog (CLAUDE.md: library code logs, never prints).
func (s *Server) resolveReachable(ctx context.Context) (reachable bool) {
	if s.cfg == nil {
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("daemon: reachability probe panicked; reporting not-reachable", "recovered", r)
			reachable = false
		}
	}()
	b, err := backend.New(s.cfg, s.runner)
	if err != nil || b == nil {
		slog.Warn("daemon: backend unavailable for reachability probe", "err", err)
		return false
	}
	ip, err := b.IP(ctx)
	if err != nil || ip == "" {
		return false
	}
	return true
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
