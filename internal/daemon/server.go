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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/push"
	"github.com/abysslink/abysslink/internal/session"
	"github.com/abysslink/abysslink/internal/shell"
)

// SessionSource is the daemon-side view of the tmux session registry: the
// one method GET /sessions needs. It is a small daemon-owned interface (not
// the concrete *session.Registry) so tests can wire a fake and the daemon
// imports internal/session only for the Snapshot types (one-way, no cycle).
type SessionSource interface {
	Snapshot() session.Snapshot
}

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
	// idleTO closes keep-alive connections that have sat idle so one-shot
	// clients that skip CloseIdleConnections cannot pin conns (and their
	// readLoop/writeLoop goroutines) on the daemon forever.
	idleTO = 60 * time.Second
	// socketProbeTimeout bounds the pre-listen liveness dial that prevents a
	// second daemon instance from stealing a live daemon's socket.
	socketProbeTimeout = 500 * time.Millisecond
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
	// sessionSource is the tmux session registry view served by GET /sessions
	// (plan 27-07). nil unless the composition root wires it via
	// SetSessionRegistry; handleSessions then reports "registry: disabled"
	// (nil-safe, never an error).
	sessionSource SessionSource

	// Phase 28 content listener state (BACK-06/BACK-07). devices, auditApp,
	// and contentTLS are injected by the composition root (SetDeviceStore /
	// SetAuditAppender / SetContentTLS); a missing dependency disables the
	// content listener (fail closed) while the daemon keeps running.
	devices    DeviceStore
	auditApp   AuditAppender
	contentTLS ContentTLSProvider
	// contentResolver is the tailnet-IP seam; nil means the production
	// backendIPResolver (tests inject a stub).
	contentResolver tailnetIPResolver
	// contentHostResolver is the MagicDNS-hostname seam used to ADVERTISE a
	// TLS-verifiable fetch URL host; nil means the production
	// backendHostResolver (tests inject a stub). A missing/non-ts.net hostname
	// falls back to the bind IP (degraded, never fail-closed — see
	// resolveContentAdvertiseHost).
	contentHostResolver tailnetHostResolver
	// content is the memory-first TTL'd token→body store.
	content *contentStore
	// contentWG tracks the content listener's shutdown drain so Run's
	// graceful-shutdown path can wait for it (clean shutdown drains).
	contentWG sync.WaitGroup
	// ackReceived counts BACK-07 ack receipts (memory-only, reset on restart).
	ackReceived atomic.Uint64

	// Phase 29 push gateway (D-06 / D-10 / D-19).
	// outbox is the bbolt-backed persistent send queue; nil when the daemon
	// starts without a configured outbox (graceful degrade: fan-out is skipped).
	// gatewayCounters are the six D-19 atomic metrics reported on GET /status.
	outbox          *push.Outbox
	gatewayCounters *push.GatewayCounters
	// gatewayCredsStatus is the push-creds-keychain doctor signal (WR-01):
	// "ok" when the gateway's keychain-backed auth path is available,
	// "unavailable" when the keychain backend is absent, "" when the push
	// gateway is not wired (older-daemon / push-disabled — omitted on /status).
	// Set once by the composition root via SetGatewayCredsStatus.
	gatewayCredsStatus string

	// Phase 30 approve/deny capability-URL loop (APPR-02/APPR-03/APPR-04).
	// approveRegistry holds the in-flight pending approval requests; nil
	// disables the approve capability routes gracefully (503 on the IPC paths,
	// 404 on the content-mux approve/deny handlers).
	approveRegistry *approve.Registry
	// approveHMACKey is the HMAC key injected by the composition root for
	// D-16 capability-URL integrity verification in handleApprove/handleDeny.
	// When nil, HMAC verification is skipped with a warning (graceful degrade:
	// approve still works, the defense-in-depth layer is absent).
	approveHMACKey []byte
	// approvePending is the count of currently-open pending approve requests
	// (can go negative briefly in race; use int64).
	approvePending atomic.Int64
	// approveApproved counts requests resolved to approved since daemon start.
	approveApproved atomic.Uint64
	// approveDenied counts requests resolved to denied since daemon start.
	approveDenied atomic.Uint64

	contentMu     sync.Mutex
	contentLive   bool
	contentHost   string
	contentPort   int
	contentStatus string
	// contentAdvertiseHost is the host placed in the minted FetchRef URL: the
	// node's *.ts.net MagicDNS name when available (so a TLS-verifying phone
	// fetch verifies against the Tailscale-issued cert SAN), otherwise the bind
	// IP as a degraded fallback. The listener still BINDS contentHost (the
	// tailnet IP) regardless (Finding 2).
	contentAdvertiseHost string
}

// NewServer returns a Server. notifier MUST be a direct backend (see Notifier).
func NewServer(notifier Notifier, runner shell.Runner, cfg *config.Config) *Server {
	return &Server{
		notifier:      notifier,
		runner:        runner,
		cfg:           cfg,
		socketPath:    SocketPath(),
		startedAt:     time.Now(),
		dispatch:      newDispatcher(notifier, cfg),
		hostname:      notifyv2.ShortHostname(),
		content:       newContentStore(nil),
		contentStatus: "disabled: content listener not started",
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

// SetSessionRegistry injects the tmux session registry served by GET
// /sessions (BACK-04). Called by the composition root when
// session_registry.enabled is true; nil-safe: when unset (or set to nil),
// handleSessions reports "registry: disabled" with an empty sessions list.
func (s *Server) SetSessionRegistry(src SessionSource) { s.sessionSource = src }

// SetOutbox injects the Phase 29 push outbox and gateway counter set.
// Called by the composition root before Run. When nil, fanOutToDevices is a
// no-op so a daemon without a configured push outbox still starts cleanly
// (no push fan-out, just the existing ntfy/legacy path).
func (s *Server) SetOutbox(o *push.Outbox, c *push.GatewayCounters) {
	s.outbox = o
	s.gatewayCounters = c
}

// SetGatewayCredsStatus records the push-creds-keychain doctor signal (WR-01)
// the daemon emits on GET /status as gateway_creds_status. Called by the
// composition root after probing the gateway's keychain-backed auth path:
// "ok" (auth path available) or "unavailable" (keychain backend absent). When
// left unset (push gateway not wired), /status omits the field so an older-style
// no-push daemon and a current push daemon stay distinguishable to doctor.
func (s *Server) SetGatewayCredsStatus(status string) { s.gatewayCredsStatus = status }

// SetApproveRegistry injects the Phase 30 pending-request registry used by the
// approve/deny capability-URL handlers and the unix-socket approve IPC routes.
// Called by the composition root before Run; nil-safe: without it the approve
// routes return 503 (graceful degrade) while the daemon keeps running.
func (s *Server) SetApproveRegistry(r *approve.Registry) { s.approveRegistry = r }

// SetApproveHMACKey injects the HMAC key used for D-16 capability-URL integrity
// verification in handleApprove/handleDeny. When nil, verification is skipped
// with a warning (graceful degrade — approve still functions, defense-in-depth
// absent). The key is the same audit-hmac keychain key as SignedAudit.
func (s *Server) SetApproveHMACKey(key []byte) { s.approveHMACKey = key }

// fanOutToDevices fans out msg to all active enrolled devices via the persistent
// push outbox (D-10). For each active device with a push token:
//   - Dedup check: if msg_id is already in the dedup bucket and kind is NOT
//     approval_request → skip (D-07 / Phase 27 D-09).
//   - Ceiling check: if the device is at its hourly wake ceiling and kind is NOT
//     approval_request → skip and increment CeilingDropped (D-05 / research Q3).
//   - Enqueue: store an outboxEntry in the bbolt outbox with NextRetryUnix=now
//     (immediate first attempt); increment Queued counter.
//
// fanOutToDevices is intentionally fast (bbolt writes are the only I/O); the
// async retry goroutine (RunOutboxRetry) owns the actual provider-send path.
// Called from handleNotifyV2 AFTER the ntfy delivery (existing pipeline runs
// first; push adds an extra wake channel on top).
//
// nil-safe: returns immediately when the outbox or device store is not wired.
func (s *Server) fanOutToDevices(ctx context.Context, msg notifyv2.Message) error {
	if s.outbox == nil || s.gatewayCounters == nil || s.devices == nil {
		return nil // no push outbox wired — graceful degrade
	}

	// Dedup check for non-approval_request: skip the entire fan-out if this
	// msg_id has already been dispatched (D-07 / Phase 27 D-09 carried forward).
	// approval_request is always exempt from dedup.
	//
	// WR-05: a dedup-STORE error (bbolt transient) is NOT an intentional skip —
	// collapsing it into a silent `return nil` drops the wake for every device
	// with no signal. Treat a store error as "not seen, proceed" (fail-open: a
	// possible duplicate wake is far less harmful than a silently-lost one) and
	// emit a greppable WARN so a flapping outbox DB is observable. Only a genuine
	// `seen == true` is an intentional, silent (debug-level) skip.
	if msg.Kind != notifyv2.KindApprovalRequest {
		seen, err := s.outbox.DedupSeen(msg.MsgID)
		switch {
		case err != nil:
			// WR-01: a dedup-store error proceeds fail-open (no retry scheduled),
			// so it is a FanoutErrors event, not a BackoffPending one — counting
			// it as pending-retry would inflate the /status retry depth.
			s.gatewayCounters.FanoutErrors.Add(1)
			slog.Warn("daemon: fanout dedup-store error; proceeding without dedup (fail-open)",
				"msg_id", msg.MsgID, "err", err)
		case seen:
			slog.Debug("daemon: fanout dedup skip", "msg_id", msg.MsgID)
			return nil
		}
	}

	// Serialize msg to JSON for the outbox MetaJSON field (routing metadata only).
	// WR-05: a marshal failure loses the wake for ALL devices — count it so a
	// systematic encode failure is observable on /status, not just a lone log.
	// WR-01: the wake is DROPPED here (no retry scheduled), so it belongs to
	// FanoutErrors, not the pending-retry BackoffPending counter.
	metaJSON, err := json.Marshal(msg)
	if err != nil {
		s.gatewayCounters.FanoutErrors.Add(1)
		slog.Warn("daemon: fanout msg marshal failed; wake lost for all devices", "msg_id", msg.MsgID, "err", err)
		return nil
	}

	records := s.devices.List()
	meta := string(metaJSON)
	for _, r := range records {
		s.enqueueDeviceWake(msg, r, meta)
	}
	return nil
}

// enqueueDeviceWake enqueues one device's wake during fan-out. Extracted from
// fanOutToDevices to keep that function under the gocyclo ceiling; the per-device
// decision tree (skip revoked/token-less, per-device ceiling, route, enqueue,
// ceiling increment) lives here. Counter/log semantics are unchanged
// (WR-01/02/05): every drop/skip path that schedules no retry increments
// FanoutErrors, a genuine ceiling rejection increments CeilingDropped, and the
// per-device window is incremented atomically at the ceiling admission check
// (CeilingCheckAndIncr, IN-01) — not at delivery, and no longer as a separate
// post-enqueue step.
func (s *Server) enqueueDeviceWake(msg notifyv2.Message, r device.Record, metaJSON string) {
	if r.Revoked || r.PushToken == "" {
		return // skip revoked or token-less devices
	}
	// Per-device ceiling check + window increment, atomic in one bbolt txn
	// (D-05 / WR-02 / IN-01). Folding admit and consume into a single transaction
	// closes the check-then-act race two concurrent fan-outs for the same device
	// could exploit. approval_request is exempt inside CeilingCheckAndIncr
	// (admitted, does not consume the window). The slot is consumed here at
	// admission, not at successful enqueue: a later enqueue failure (rare, counted
	// as FanoutErrors below) does not refund it — the ceiling counts admitted wakes.
	if msg.Kind != notifyv2.KindApprovalRequest {
		allowed, cerr := s.outbox.CeilingCheckAndIncr(r.ID, msg.Kind, push.DefaultCeiling)
		if cerr != nil {
			// WR-05/WR-01: a ceiling-STORE error is a storage failure, not an
			// intentional drop, and schedules no retry — count it as a FanoutErrors
			// signal and skip only this device, never the whole fan-out.
			s.gatewayCounters.FanoutErrors.Add(1)
			slog.Warn("daemon: fanout ceiling-store error; skipping device",
				"device_id", r.ID, "err", cerr)
			return
		}
		if !allowed {
			s.gatewayCounters.CeilingDropped.Add(1)
			slog.Debug("daemon: fanout ceiling drop",
				"device_id", r.ID, "msg_id", msg.MsgID, "kind", msg.Kind)
			return
		}
	}

	// WR-03: route by the device record's platform via devicePlatform rather than
	// a bare "unifiedpush" literal. The current enrollment schema (device.Record)
	// carries no platform-specific token, so every enrolled device IS a UnifiedPush
	// endpoint (its PushToken is the ntfy endpoint URL, the sovereign default —
	// D-18). devicePlatform is the single seam to update when the v5 app adds a
	// platform field to device.Record.
	cid := push.CollapseID(msg.MsgID, msg.Session.Session, msg.Kind)
	entry := push.OutboxEntry{
		Platform:       devicePlatform(r),
		ProviderToken:  r.PushToken, // secret-class — never log (D-17)
		MsgID:          msg.MsgID,
		Title:          msg.Title,
		MetaJSON:       metaJSON,
		Attempts:       0,
		FirstTriedUnix: time.Now().Unix(),
		NextRetryUnix:  time.Now().Unix(), // immediate first attempt
		CollapseID:     cid,
	}
	if err := s.outbox.Enqueue(r.ID, entry); err != nil {
		// WR-05/WR-01: an enqueue failure drops this device's wake with no retry
		// scheduled — count it as a FanoutErrors signal and skip only this device.
		s.gatewayCounters.FanoutErrors.Add(1)
		slog.Warn("daemon: fanout enqueue failed; wake lost for device",
			"device_id", r.ID, "msg_id", msg.MsgID, "err", err)
		return
	}
	s.gatewayCounters.Queued.Add(1)
	// The per-device window was already incremented atomically in
	// CeilingCheckAndIncr above (IN-01) — no separate post-enqueue increment.
}

// devicePlatform returns the push platform for a device record (WR-03). The
// current enrollment schema (device.Record) has no platform field, so every
// enrolled device is a UnifiedPush endpoint (its PushToken IS the ntfy endpoint
// URL — the sovereign default, D-18). This is the single seam to update when
// the v5 app adds a platform field to device.Record: returning the record's
// real platform here routes APNs/FCM devices to their own legs instead of
// mis-routing them through the UnifiedPush gateway.
func devicePlatform(_ device.Record) string {
	return push.PlatformUnifiedPush
}

// Run listens on the Unix socket and starts watchers until ctx is cancelled.
// On cancellation it waits for the graceful shutdown (connection drain +
// socket-file removal) to complete before returning (NET-14) so the process
// cannot exit mid-drain or leave a stale socket file behind.
func (s *Server) Run(ctx context.Context) error {
	if s.socketPath == "" {
		// SocketPath failed closed (NET-13: socket dir verification failed).
		return fmt.Errorf("daemon: no usable socket path (socket directory verification failed — see prior log)")
	}
	if err := ensureSocketFree(s.socketPath); err != nil {
		return err
	}
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("daemon: listen %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("daemon: chmod socket: %w", err)
	}

	mux := s.buildUnixMux()
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: readHeaderTO, IdleTimeout: idleTO}

	s.startWatchers(ctx)
	// v2 dispatch retry loop (D-28); exits on ctx cancellation.
	go s.dispatch.run(ctx)
	// Tailnet-only HTTPS content listener (BACK-06). Launched async because
	// the bind resolution probes the backend; every failure path disables the
	// listener (fail closed) while this socket keeps serving.
	go s.startContentServer(ctx)

	// Graceful-shutdown goroutine: by the time srv.Shutdown runs, ctx is
	// already Done, so the drain needs a context detached from that
	// cancellation (WithoutCancel keeps ctx values) plus its own timeout.
	// runCtx exists so a real Serve() error — where ctx is still live — can
	// also wake this goroutine for the NET-14 cleanup (drain + socket removal)
	// instead of leaking it and the socket file.
	runCtx, stopShutdown := context.WithCancel(ctx)
	defer stopShutdown()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-runCtx.Done()
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = os.Remove(s.socketPath)
		// Wait for the content listener's own drain (BACK-06): its shutdown
		// goroutine registered with contentWG when the listener went live.
		s.contentWG.Wait()
	}()

	slog.Info("abysslinkd listening", "socket", s.socketPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// A real Serve error: trigger the shutdown goroutine and wait for it so
		// the socket file is removed and the goroutine stopped (NET-14).
		stopShutdown()
		<-shutdownDone
		return fmt.Errorf("daemon: serve: %w", err)
	}
	// Serve returned ErrServerClosed, which only srv.Shutdown (in the goroutine
	// above) can trigger. Wait for the drain and socket-file removal to finish
	// before returning so the caller cannot exit mid-shutdown (NET-14).
	<-shutdownDone
	return nil
}

// ensureSocketFree guards against a second daemon instance stealing a live
// daemon's socket: an unconditional pre-listen os.Remove would unlink the
// serving daemon's socket, and the usurper's later shutdown would then delete
// the survivor's file. It probes the path with a short unix dial:
//   - dial answers → another abysslinkd is serving; refuse to start.
//   - ECONNREFUSED → stale file from a crashed daemon; remove it.
//   - file does not exist → nothing to clear.
//   - anything else → ambiguous; fail closed without removing.
func ensureSocketFree(path string) error {
	conn, err := net.DialTimeout("unix", path, socketProbeTimeout)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("daemon: another abysslinkd is already serving %s — refusing to start", path)
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case errors.Is(err, syscall.ECONNREFUSED):
		if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
			return fmt.Errorf("daemon: clear stale socket: %w", rerr)
		}
		return nil
	default:
		return fmt.Errorf("daemon: cannot verify whether socket %s is live: %w", path, err)
	}
}

// buildUnixMux returns the unix-socket mux. Extracted from Run so tests can
// construct it directly without starting a real listener. All routes here are
// local-only (WR-04) — they MUST NOT be moved onto buildContentMux.
func (s *Server) buildUnixMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/notify", s.handleNotify)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/sessions", s.handleSessions)
	// BACK-09: the local staging seam. This route accepts a SECRET credential
	// bundle in the request body, so it lives ONLY on this chmod-0600 unix
	// socket (the local trust root) — NEVER on buildContentMux (the network TLS
	// mux). Do not move it.
	mux.HandleFunc("/enroll/stage", s.handleEnrollStage)
	// Phase 30 approve IPC (WR-04): unix-socket only — NEVER on content mux.
	// POST /approve/request: mint approve+deny capability URLs, register pending req.
	// GET /approve/wait/{id}: long-poll until resolution or timeout.
	mux.HandleFunc("POST /approve/request", s.handleApproveRequest)
	mux.HandleFunc("GET /approve/wait/{id}", s.handleApproveWait)
	return mux
}

// approveTTLDuration returns the TTL for approve/deny capability URLs: the
// configured approval timeout plus a 30-second buffer so URLs don't expire
// before the timeout fires. Default: 150s (120s + 30s).
func (s *Server) approveTTLDuration() time.Duration {
	if s.cfg != nil && s.cfg.Approval.TimeoutSeconds > 0 {
		return time.Duration(s.cfg.Approval.TimeoutSeconds)*time.Second + 30*time.Second
	}
	return 150 * time.Second // default: 120s + 30s buffer
}

// approveTimeoutDuration returns the wait timeout for handleApproveWait (the
// configured approval timeout; default 120s).
func (s *Server) approveTimeoutDuration() time.Duration {
	if s.cfg != nil && s.cfg.Approval.TimeoutSeconds > 0 {
		return time.Duration(s.cfg.Approval.TimeoutSeconds) * time.Second
	}
	return 120 * time.Second
}

// approveRequestBody is the POST /approve/request JSON body.
type approveRequestBody struct {
	Action        string   `json:"action"`
	ClosureHash   string   `json:"closure_hash"` // hex-encoded 32 bytes
	DeclaredTier  int      `json:"declared_tier"`
	ExtraCritical []string `json:"extra_critical"`
}

// approveRequestResponse is the POST /approve/request JSON response.
type approveRequestResponse struct {
	RequestID  string `json:"request_id"`
	ApproveURL string `json:"approve_url"`
	DenyURL    string `json:"deny_url"`
	ExpiresAt  string `json:"expires_at"`
}

// decodeApproveRequest decodes + validates the POST /approve/request body.
// Returns the request struct, parsed closure hash, and ok=false (with 4xx
// already written) on any error. Extracted from handleApproveRequest to keep
// that function under the gocyclo ceiling.
func decodeApproveRequest(w http.ResponseWriter, r *http.Request) (approveRequestBody, [32]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAckBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req approveRequestBody
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid approve request payload", http.StatusBadRequest)
		return req, [32]byte{}, false
	}
	if strings.TrimSpace(req.Action) == "" {
		http.Error(w, "action is required", http.StatusBadRequest)
		return req, [32]byte{}, false
	}
	if len(req.ClosureHash) != 64 {
		http.Error(w, "closure_hash must be 64 hex characters (32 bytes)", http.StatusBadRequest)
		return req, [32]byte{}, false
	}
	closureHashBytes, err := hex.DecodeString(req.ClosureHash)
	if err != nil || len(closureHashBytes) != 32 {
		http.Error(w, "closure_hash is not valid hex", http.StatusBadRequest)
		return req, [32]byte{}, false
	}
	if req.DeclaredTier < 0 || req.DeclaredTier > 2 {
		http.Error(w, "declared_tier must be 0, 1, or 2", http.StatusBadRequest)
		return req, [32]byte{}, false
	}
	var closureHash [32]byte
	copy(closureHash[:], closureHashBytes)
	return req, closureHash, true
}

// openApproveRegistryEntry registers the approve+deny entries in the registry.
// The approve HMAC sig is stored on the main entry (for handleApprove to verify);
// the deny HMAC sig is stored on a side-channel keyed requestID+":deny" (for
// handleDeny). Extracted from handleApproveRequest to keep cyclomatic complexity
// below the gocyclo ceiling.
func (s *Server) openApproveRegistryEntry(requestID string, closureHash [32]byte, tier approve.TierLevel, action string) (string, string, error) {
	var approveSig, denySig string
	if len(s.approveHMACKey) > 0 {
		approveSig = approve.SignApproveURL(s.approveHMACKey, requestID, "approve", closureHash)
		denySig = approve.SignApproveURL(s.approveHMACKey, requestID, "deny", closureHash)
	} else {
		slog.Warn("daemon: approve HMAC key not set — capability URLs lack integrity signature (D-16 defense-in-depth absent)")
	}
	if _, err := s.approveRegistry.Open(requestID, closureHash, tier, approveSig,
		approve.WithActionName(action)); err != nil {
		return "", "", err
	}
	// Side-channel: store deny sig under requestID+":deny" so handleDeny can
	// look it up without adding a second field to pendingReq.
	if denySig != "" {
		denySigKey := requestID + ":deny"
		var zeroClosure [32]byte
		if _, err2 := s.approveRegistry.Open(denySigKey, zeroClosure, approve.TierBenign, denySig); err2 != nil {
			slog.Debug("daemon: deny sig side-channel open failed", "err", err2)
		}
	}
	return approveSig, denySig, nil
}

// handleApproveRequest serves POST /approve/request on the unix socket ONLY
// (WR-04). It validates the request, force-upgrades tier, mints capability URLs,
// registers the pending request, and returns the approve/deny URLs to the CLI.
// Critical-tier actions are rejected with 403 (D-07).
//
// SECURITY: capability URLs are never logged (T-30-10); only requestID[:8] and
// tier are observable. No URL, token, or full requestID ever reaches slog.
func (s *Server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	req, closureHash, ok := decodeApproveRequest(w, r)
	if !ok {
		return
	}

	// Force-upgrade tier: check in-code critical patterns + extraCritical.
	effectiveTier := approve.Tier(approve.TierLevel(req.DeclaredTier), req.Action, req.ExtraCritical)
	if effectiveTier == approve.TierCritical {
		http.Error(w, `{"error":"critical tier actions require TTY approval (D-07)"}`, http.StatusForbidden)
		return
	}
	if s.approveRegistry == nil {
		http.Error(w, "approve registry not available", http.StatusServiceUnavailable)
		return
	}

	requestID := notifyv2.NewMsgID()
	if _, _, err := s.openApproveRegistryEntry(requestID, closureHash, effectiveTier, req.Action); err != nil {
		slog.Warn("daemon: approve registry open failed", "request_id", requestID[:8], "err", err)
		http.Error(w, "approve registry open failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ttl := s.approveTTLDuration()
	approveToken, expiresAt := s.content.mintApprove(requestID, ttl)
	denyToken, _ := s.content.mintDeny(requestID, ttl)
	s.approvePending.Add(1)

	s.contentMu.Lock()
	advertiseHost, port := s.contentAdvertiseHost, s.contentPort
	s.contentMu.Unlock()
	if advertiseHost == "" {
		advertiseHost = "127.0.0.1"
	}
	if port == 0 {
		port = 2587
	}
	hostPort := net.JoinHostPort(advertiseHost, strconv.Itoa(port))
	approveURL := "https://" + hostPort + "/approve/" + approveToken
	denyURL := "https://" + hostPort + "/deny/" + denyToken

	// Log only safe metadata — never URLs, tokens, or full requestID (T-30-10).
	slog.Info("daemon: approve request opened",
		"request_id", requestID[:8], "tier", effectiveTier, "ttl_seconds", int(ttl/time.Second))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(approveRequestResponse{
		RequestID:  requestID,
		ApproveURL: approveURL,
		DenyURL:    denyURL,
		ExpiresAt:  expiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		slog.Warn("daemon: approve request encode failed", "err", err)
	}
}

// approveWaitResponse is the GET /approve/wait/{id} JSON response.
type approveWaitResponse struct {
	Approved  bool   `json:"approved"`
	RequestID string `json:"request_id"`
}

// handleApproveWait serves GET /approve/wait/{id} on the unix socket ONLY
// (WR-04). It long-polls the approve registry until the request resolves or
// the context expires. On timeout it returns 408; on resolution it returns 200.
// hasTTY is always false on the unix-socket path — the CLI's TTY fallback is
// handled CLI-side, not daemon-side.
func (s *Server) handleApproveWait(w http.ResponseWriter, r *http.Request) {
	requestID := r.PathValue("id")
	if requestID == "" {
		http.Error(w, "request_id is required", http.StatusBadRequest)
		return
	}

	if s.approveRegistry == nil {
		http.Error(w, `{"error":"approve registry not available"}`, http.StatusServiceUnavailable)
		return
	}

	// Look up the pending request.
	hmacSig, closureHash, tier, ok := s.approveRegistry.Lookup(requestID)
	if !ok {
		http.Error(w, `{"error":"request not found"}`, http.StatusNotFound)
		return
	}
	// Reconstruct the pendingReq accessor: we need to call Wait, which takes
	// a *pendingReq. Since pendingReq is unexported, we use a helper approach:
	// resolve the pending req by re-looking it up and calling Wait via the
	// registry's exported Wait method that takes a request ID.
	// The approve.Registry.Wait takes *pendingReq which is unexported.
	// DESIGN ADJUSTMENT: We need to expose a WaitByID method or similar.
	// We'll use a timeout context and poll the registry for resolution.
	_ = hmacSig
	_ = closureHash
	_ = tier

	// Build a timeout context from the configured approval timeout.
	timeout := s.approveTimeoutDuration()
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// Poll via WaitByID — we need this method on Registry.
	res, waitErr := s.approveRegistry.WaitByID(ctx, requestID, false)
	if waitErr != nil {
		if errors.Is(waitErr, approve.ErrTimeout) || errors.Is(waitErr, context.DeadlineExceeded) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestTimeout)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":    "timeout",
				"approved": false,
			})
			return
		}
		// ErrDenied — treat as a valid denial response (200 with approved:false).
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(approveWaitResponse{
		Approved:  res.Approved,
		RequestID: requestID[:8],
	}); err != nil {
		slog.Warn("daemon: approve wait encode failed", "err", err)
	}
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
		// here to return 413 explicitly for clarity. Typed match — a substring
		// match on the error text would break on wording changes and could
		// mislabel other read errors.
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		// Not a JSON problem — the body could not be read at all (e.g. the
		// client hung up mid-body).
		http.Error(w, "failed to read request body", http.StatusBadRequest)
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

// notifyV2Envelope is the unix-socket v2 envelope (Phase 28): the wire
// Message plus an OPTIONAL content field. Content never enters the Message
// struct itself — the daemon mints a content-store token and the message
// carries only the FetchRef (BACK-06). DisallowUnknownFields semantics are
// preserved for everything else: "content" is the single additional key the
// decoder accepts; any other body-shaped key is still unknown by
// construction (D-17).
type notifyV2Envelope struct {
	notifyv2.Message
	Content string `json:"content,omitempty"`
}

// handleNotifyV2 is the POST /notify v2 branch (BACK-05): strict decode
// (DisallowUnknownFields — the D-17 decode gate: Message has no body field,
// so any body/content-shaped key is unknown by construction; the optional
// envelope content field is hived off into the content store, never the
// message), server-side enrichment, Validate, then dispatch through the
// policy engine. Explicit POSTs bypass the heuristic cooldown by origin
// (D-10). Display-name enrichment from the registry arrives with the bridge
// in plan 27-07.
func (s *Server) handleNotifyV2(w http.ResponseWriter, r *http.Request, raw []byte) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env notifyV2Envelope
	if err := dec.Decode(&env); err != nil {
		http.Error(w, "invalid v2 payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	msg := env.Message

	// Enrichment before validation: hook/CLI consumers may omit msg_id and
	// host; the daemon fills both server-side.
	if msg.MsgID == "" {
		msg.MsgID = notifyv2.NewMsgID()
	}
	if msg.Host == "" {
		msg.Host = s.hostname
	}

	// Optional content → content-store token → FetchRef (BACK-06). The body
	// is capped at 64 KiB (413 beyond); a caller-supplied fetch alongside
	// content is ambiguous and rejected. When the content listener is down
	// the content is DROPPED and the wake dispatches unchanged — the
	// fallback title carries it (BACK-08); content is never queued or
	// persisted (D-13 spirit).
	if len(env.Content) > maxContentBodyBytes {
		http.Error(w, "content too large", http.StatusRequestEntityTooLarge)
		return
	}
	if env.Content != "" {
		if msg.Fetch != nil {
			http.Error(w, "content and fetch are mutually exclusive", http.StatusBadRequest)
			return
		}
		if u, ttl, ok := s.mintFetchRef(env.Content); ok {
			msg.Fetch = &notifyv2.FetchRef{URLTailnet: u, TTLSeconds: ttl}
		} else {
			slog.Debug("daemon: content dropped — content listener down; dispatching wake with fallback title only (BACK-08)",
				"msg_id", msg.MsgID, "kind", msg.Kind)
		}
	}

	// Single validation gate: dispatch's policy-side Validate (its first step)
	// is the one gate; its error surfaces here as the 422 with the accurate
	// reason. A handler-side pre-Validate would be a duplicate of the same
	// check on the same (enriched) message.
	//
	// Delivery runs under WithoutCancel: the CLI client posts with a 2s
	// timeout while the synchronous ntfy leg can take ~5s. If the client's
	// disconnect cancelled delivery here, the daemon would queue the note for
	// retry while the timed-out client falls back to a direct send — the same
	// note delivered twice. Detaching from the request context makes the
	// daemon's accepted-request delivery authoritative.
	if err := s.dispatch.dispatch(context.WithoutCancel(r.Context()), msg, originExplicit, notifyv2.RenderOpts{}); err != nil {
		slog.Warn("daemon: v2 notify rejected", "reason", err)
		http.Error(w, "invalid v2 message: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// Phase 29 push fan-out (D-10): enqueue to all enrolled devices via the
	// persistent push outbox after the ntfy delivery succeeds. nil-safe: no-op
	// when the outbox is not wired (daemon started without Phase 29 push config).
	// Errors are logged internally; fan-out failure does not 500 the caller.
	_ = s.fanOutToDevices(context.WithoutCancel(r.Context()), msg)

	// Mirror the v1 ring-adder with METADATA ONLY (T-19-19): msg_id, kind,
	// pane — never anything body-like (the schema has no body field anyway).
	// The recorded priority is the post-render ntfy numeric value ("3"/"4"/"5"
	// via D-14), not the raw wire word — v1 records ntfy numeric strings, so
	// the webui history stays consistent across both paths.
	if s.ring != nil {
		parts := []string{string(msg.Kind)}
		if msg.Session.Pane != "" {
			parts = append(parts, msg.Session.Pane)
		}
		parts = append(parts, msg.MsgID)
		s.ring.AddEvent(strings.Join(parts, " "), "", notifyv2.Render(msg, notifyv2.RenderOpts{}).Priority, time.Now())
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

	// Phase 30 approve counters (APPR-02): current pending + totals since start.
	// All three use omitempty so an older daemon that does not set the registry
	// reports nothing rather than fabricated zeros. approvePending is int64
	// (can momentarily go negative in a race); approve_approved/denied are
	// monotonic uint64.
	ApprovePending  int64  `json:"approve_pending,omitempty"`
	ApproveApproved uint64 `json:"approve_approved,omitempty"`
	ApproveDenied   uint64 `json:"approve_denied,omitempty"`

	// GateExecsObserved is live: it reads the gate decorator's atomic counter
	// via SetExecCounter — the count of module/consumer execs the observe-only
	// GatedRunner has intercepted (D-38); 0 when no gate is wired.
	GateExecsObserved uint64 `json:"gate_execs_observed"`

	// WakeSent counts v2 notes the dispatcher successfully delivered
	// (including retry-queue successes); AckReceived counts BACK-07 phone
	// acks. Both are memory-only and reset on daemon restart — wake-sent vs
	// ack-received is reported separately by design (BACK-07), and a gap
	// between them triggers NOTHING (no re-wake logic exists).
	WakeSent    uint64 `json:"wake_sent"`
	AckReceived uint64 `json:"ack_received"`

	// ContentStore reports the BACK-06 content listener state:
	// "listening on <addr>" or "disabled: <reason>".
	ContentStore string `json:"content_store"`

	// Devices is the per-device DEVC-04 surface (name, last-seen, stale,
	// revoked) the CLI renders. Empty when no device store is wired.
	Devices []daemonDeviceStatus `json:"devices"`

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

	// Phase 29 push gateway counters (D-19): aggregate delivery metrics.
	// All seven fields are omitempty so the JSON stays backward-compatible when
	// the push outbox is not wired (zero values are omitted). No device token,
	// provider credential, or per-device detail is ever included (D-17 / T-29-04-4).
	GatewayQueued       int `json:"gateway_queued,omitempty"`
	GatewaySent         int `json:"gateway_sent,omitempty"`
	GatewayAccepted     int `json:"gateway_provider_accepted,omitempty"`
	GatewayPruned       int `json:"gateway_pruned_tokens,omitempty"`
	GatewayCeiling      int `json:"gateway_ceiling_dropped,omitempty"`
	GatewayBackoff      int `json:"gateway_backoff_pending,omitempty"`
	GatewayFanoutErrors int `json:"gateway_fanout_errors,omitempty"`

	// GatewayCredsStatus is the push-creds-keychain doctor signal (WR-01):
	// "ok" (gateway auth path available) or "unavailable" (keychain backend
	// absent). omitempty so a daemon without a wired push gateway omits it and
	// the doctor check reports the honest "older daemon / not wired" default
	// instead of a fabricated outcome. No credential material is ever included.
	GatewayCredsStatus string `json:"gateway_creds_status,omitempty"`
}

// daemonDoctorSummary is the per-severity doctor finding count in /status.
type daemonDoctorSummary struct {
	Fatal int `json:"fatal"`
	Warn  int `json:"warn"`
	Pass  int `json:"pass"`
}

// daemonDeviceStatus is one enrolled device in /status (DEVC-04): name,
// last-seen, staleness against the 7-day window, and revocation. No push
// token, bearer hash, or key material is ever exposed here.
type daemonDeviceStatus struct {
	Name     string `json:"name"`
	LastSeen string `json:"last_seen,omitempty"`
	Stale    bool   `json:"stale"`
	Revoked  bool   `json:"revoked"`
}

// deviceStatuses builds the /status devices block from the device store:
// every record (active and revoked) with its DEVC-04 staleness computed via
// Stale(7d). nil-safe: without a device store it returns an empty list.
func (s *Server) deviceStatuses() []daemonDeviceStatus {
	out := []daemonDeviceStatus{}
	if s.devices == nil {
		return out
	}
	staleIDs := make(map[string]bool)
	for _, r := range s.devices.Stale(staleDeviceWindow) {
		staleIDs[r.ID] = true
	}
	for _, r := range s.devices.List() {
		d := daemonDeviceStatus{
			Name:    r.Name,
			Stale:   staleIDs[r.ID],
			Revoked: r.Revoked,
		}
		if !r.LastSeen.IsZero() {
			d.LastSeen = r.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, d)
	}
	return out
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

	// Phase 29 gateway counters (D-19): read from the atomic fields. When the
	// outbox is not wired all counters stay 0 and are omitted (omitempty).
	var (
		gwQueued       int
		gwSent         int
		gwAccepted     int
		gwPruned       int
		gwCeiling      int
		gwBackoff      int
		gwFanoutErrors int
	)
	if s.gatewayCounters != nil {
		gwQueued = int(s.gatewayCounters.Queued.Load())             //nolint:gosec // G115: counter is non-negative
		gwSent = int(s.gatewayCounters.Sent.Load())                 //nolint:gosec // G115: counter is non-negative
		gwAccepted = int(s.gatewayCounters.ProviderAccepted.Load()) //nolint:gosec // G115: counter is non-negative
		gwPruned = int(s.gatewayCounters.PrunedTokens.Load())       //nolint:gosec // G115: counter is non-negative
		gwCeiling = int(s.gatewayCounters.CeilingDropped.Load())    //nolint:gosec // G115: counter is non-negative
		gwBackoff = int(s.gatewayCounters.BackoffPending.Load())    //nolint:gosec // G115: counter is non-negative
		gwFanoutErrors = int(s.gatewayCounters.FanoutErrors.Load()) //nolint:gosec // G115: counter is non-negative
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
		// LIVE memory-only counters (BACK-07): wake-sent vs ack-received,
		// reported separately and never reconciled into a re-wake.
		WakeSent:     s.dispatch.wakeSentCount(),
		AckReceived:  s.ackReceived.Load(),
		ContentStore: s.contentStoreStatus(),
		Devices:      s.deviceStatuses(),
		// PostureComplete=false flags the DOCTOR summary as non-authoritative so
		// consumers do not read the zeroed doctor summary as a genuine "0 fatal"
		// all-clear on a security-posture endpoint (WR-05). Reachable is now real.
		PostureComplete: false,
		// Phase 29 push gateway counters (D-19). Zero values are omitted (omitempty).
		GatewayQueued:       gwQueued,
		GatewaySent:         gwSent,
		GatewayAccepted:     gwAccepted,
		GatewayPruned:       gwPruned,
		GatewayCeiling:      gwCeiling,
		GatewayBackoff:      gwBackoff,
		GatewayFanoutErrors: gwFanoutErrors,
		// WR-01: real push-creds-keychain signal from the composition-root probe.
		// Empty when the push gateway is not wired (omitempty drops it).
		GatewayCredsStatus: s.gatewayCredsStatus,
		// Phase 30 approve counters (APPR-02). Only reported when the approve
		// registry is wired (non-nil); omitempty elides them on older daemons.
		ApprovePending:  s.approvePending.Load(),
		ApproveApproved: s.approveApproved.Load(),
		ApproveDenied:   s.approveDenied.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("daemon: status encode failed", "err", err)
	}
}

// maxStageBody caps the POST /enroll/stage request body. The bundle carries an
// SSH private key + certificate + CA line + tokens — typically a few KiB, but a
// larger key type (e.g. RSA-4096) plus the cert can exceed 4 KiB, so it reuses
// the 64 KiB content body cap as a generous ceiling rather than the tight ack
// cap (a too-tight cap would silently degrade enrollment to the inline box on
// large keys). Still a hard bound against body flooding (T-28.2-09).
const maxStageBody = maxContentBodyBytes

// enrollStageRequest is the POST /enroll/stage body: the marshaled credential
// bundle (opaque to the daemon — served back verbatim) plus a caller-requested
// TTL (0 means the configured EffectiveEnrollTTL default).
type enrollStageRequest struct {
	Bundle     json.RawMessage `json:"bundle"`
	TTLSeconds int             `json:"ttl_seconds"`
}

// enrollStageResponse is the POST /enroll/stage reply: the one-scan capability
// URL the operator renders as a QR, and the effective (clamped) TTL.
type enrollStageResponse struct {
	URL        string `json:"url"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// clampEnrollTTL clamps a caller-requested TTL (in seconds) into the enroll
// bounds [Min,Max]EnrollTTLSeconds so a hostile or buggy caller can never mint
// an unbounded bootstrap token (T-28.2-08).
func clampEnrollTTL(seconds int) time.Duration {
	if seconds < config.MinEnrollTTLSeconds {
		seconds = config.MinEnrollTTLSeconds
	}
	if seconds > config.MaxEnrollTTLSeconds {
		seconds = config.MaxEnrollTTLSeconds
	}
	return time.Duration(seconds) * time.Second
}

// handleEnrollStage serves POST /enroll/stage on the LOCAL unix mux ONLY
// (BACK-09). The separate `enroll` CLI process POSTs a freshly minted credential
// bundle here; the daemon stages it in the in-memory content store under a
// single-use bootstrap token and returns the one-scan capability URL.
//
// SECURITY (CLAUDE.md immutables):
//   - The bundle is a SECRET and arrives only in the request body — never argv.
//   - The staged bundle is TRANSIENT daemon runtime memory (the contentStore
//     map): explicitly EXEMPT from the audit-mutation rule, exactly like the
//     BACK-06 store, and NEVER written to disk. This handler makes no audit call.
//   - No secret/url/token/bundle ever reaches a log — only ttl_seconds (opaque).
//   - When the content listener is not live the handler returns 503 (a clean
//     degrade signal so the CLI falls back to the inline box); it never panics.
func (s *Server) handleEnrollStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, ok := decodeStageRequest(w, r)
	if !ok {
		return
	}

	// Read the listener fields under contentMu exactly as mintFetchRef does.
	s.contentMu.Lock()
	live, advertiseHost, port := s.contentLive, s.contentAdvertiseHost, s.contentPort
	s.contentMu.Unlock()
	if !live {
		// Clean degrade signal — NOT an ErrUnreachable-class failure (the daemon
		// received the request); the CLI shows credentials inline instead.
		http.Error(w, "content listener not live", http.StatusServiceUnavailable)
		return
	}

	// Resolve the TTL: the configured default (nil-guard s.cfg), or the clamped
	// caller-requested value when a positive ttl_seconds is supplied.
	ttl := config.DefaultEnrollTTLSeconds * time.Second
	if s.cfg != nil {
		ttl = s.cfg.ContentStore.EffectiveEnrollTTL()
	}
	if req.TTLSeconds > 0 {
		ttl = clampEnrollTTL(req.TTLSeconds)
	}

	token, _ := s.content.mintBootstrap(string(req.Bundle), ttl)
	u := "https://" + net.JoinHostPort(advertiseHost, strconv.Itoa(port)) + "/enroll/" + token

	// Opaque ttl only — never the url, token, or credential body (T-28.2-10).
	slog.Info("daemon: staged bootstrap entry", "ttl_seconds", int(ttl/time.Second))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(enrollStageResponse{URL: u, TTLSeconds: int(ttl / time.Second)}); err != nil {
		slog.Warn("daemon: enroll-stage encode failed", "err", err)
	}
}

// decodeStageRequest caps the body, decodes the staging request with unknown
// fields rejected, and validates a non-empty bundle. It writes the 4xx response
// itself and returns ok=false on any failure (keeps handleEnrollStage's cyclo
// flat). It never logs the body.
func decodeStageRequest(w http.ResponseWriter, r *http.Request) (enrollStageRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxStageBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req enrollStageRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid stage payload", http.StatusBadRequest)
		return enrollStageRequest{}, false
	}
	if len(req.Bundle) == 0 || string(req.Bundle) == "null" {
		http.Error(w, "bundle is required", http.StatusBadRequest)
		return enrollStageRequest{}, false
	}
	return req, true
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
