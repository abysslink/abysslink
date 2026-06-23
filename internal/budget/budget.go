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

package budget

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/notifyv2"
)

// castReadCeiling is the maximum number of bytes read from the cast file before
// audit binding (T-31-09 mitigation: DoS via large cast file). 256 MiB matches
// the existing writeFilePathCeiling in internal/audit.
const castReadCeiling = 256 * 1024 * 1024

// defaultApprovalTimeout is the approval wait timeout per ladder cycle.
// After this duration with no phone response the watcher stays frozen and
// re-notifies (D-06: never auto-decide). Configurable via Config.ApprovalTimeout.
const defaultApprovalTimeout = 2 * time.Minute

// Config is the runtime configuration for Watcher. It is converted from
// config.BudgetConfig by the caller (cmd_arm.go) — it carries resolved
// duration values with defaults applied. Zero-value fields use the compiled-in
// defaults listed below.
type Config struct {
	// WallClock is the wall-clock run limit before a threshold trip.
	// Zero uses the compiled-in default of 30 minutes (D-04).
	WallClock time.Duration

	// LoopN is the number of identical closure-hash repeats in the sliding
	// window that constitutes a loop. Zero uses default 8 (D-04). Floor 2.
	LoopN int

	// LoopWindow is the command-count sliding window size. Zero uses default 20 (D-04).
	LoopWindow int

	// Ladder enables the full escalation ladder (notify → SIGSTOP → kill).
	// Default false (shadow mode — D-05). Set true to enable SIGSTOP on threshold.
	Ladder bool

	// KillGrace is the SIGTERM grace period before SIGKILL in the kill ladder.
	// Zero uses default 5s (D-07). Floor 1s, ceiling 30s.
	KillGrace time.Duration

	// ApprovalTimeout is the per-cycle wait duration for phone approval.
	// After this duration with no phone answer, the watcher re-notifies and
	// stays frozen (D-06: never auto-decide). Zero uses defaultApprovalTimeout.
	ApprovalTimeout time.Duration
}

// resolvedLoopN returns the effective loop trip count, applying the default of 8.
func (c Config) resolvedLoopN() int {
	if c.LoopN >= 2 {
		return c.LoopN
	}
	return 8
}

// resolvedLoopWindow returns the effective sliding window size, applying the default of 20.
func (c Config) resolvedLoopWindow() int {
	if c.LoopWindow >= 5 {
		return c.LoopWindow
	}
	return 20
}

// resolvedKillGrace returns the effective SIGTERM grace period, applying the
// default of 5s when KillGrace is zero (not configured). Any non-zero value
// is used as-is (tests may set very short values; production YAML validation
// enforces the 1s floor via validateBudget in internal/config).
func (c Config) resolvedKillGrace() time.Duration {
	if c.KillGrace > 0 {
		return c.KillGrace
	}
	return 5 * time.Second
}

// resolvedApprovalTimeout returns the effective approval wait duration.
func (c Config) resolvedApprovalTimeout() time.Duration {
	if c.ApprovalTimeout > 0 {
		return c.ApprovalTimeout
	}
	return defaultApprovalTimeout
}

// notifyClient is the internal interface for sending KindAgentStopped
// notifications. Implemented by the daemon IPC client in cmd_arm.go;
// injected as a fake in tests.
type notifyClient interface {
	SendAgentStopped(ctx context.Context, reason string) error
}

// auditAppender is the internal interface for writing audit-log entries.
// Implemented by *audit.Audit; injected as a fake in tests.
type auditAppender interface {
	Append(op, target string, content []byte, dryRun bool) error
}

// gatedObserver is the interface for gate.Gated — the exec-stream observer tap.
// We accept any value with SetObserver so tests can inject a fake.
type gatedObserver interface {
	SetObserver(fn func([32]byte))
}

// signalFn is the type for signal sending (injectable for tests).
// pgid is the positive process-group id; sig is the signal to send.
// The implementation uses syscall.Kill(-pgid, sig).
type signalFn func(pgid int, sig syscall.Signal) error

// defaultSignalFn is the production signal sender: syscall.Kill(-pgid, sig).
func defaultSignalFn(pgid int, sig syscall.Signal) error {
	return syscall.Kill(-pgid, sig) //nolint:gosec // G104: budget watcher intentionally sends signals to the process group
}

// loopDetector is a fixed-size ring buffer of hex-encoded closure hashes
// (RESEARCH.md Pattern 2). It trips when the same hash appears ≥ tripN times
// within the last windowSize entries. Hashes are stored as hex strings to avoid
// [32]byte comparison edge cases (Pitfall 5).
type loopDetector struct {
	window     []string // ring buffer, len = windowSize; stores hex(hash)
	head       int      // next write index (wraps mod windowSize)
	size       int      // number of entries filled (saturates at windowSize)
	windowSize int      // M — sliding window capacity
	tripN      int      // N — identical-hash count required to trip
}

// push adds hash to the ring buffer and returns true if the hash now appears
// ≥ tripN times within the filled window. It is NOT safe for concurrent use;
// the caller (Watch) must ensure single-goroutine access.
func (d *loopDetector) push(hash [32]byte) bool {
	s := hex.EncodeToString(hash[:])
	d.window[d.head%d.windowSize] = s
	d.head++
	if d.size < d.windowSize {
		d.size++
	}
	count := 0
	for i := 0; i < d.size; i++ {
		if d.window[i] == s {
			count++
		}
	}
	return count >= d.tripN
}

// Watcher drives the budget observation + escalation state machine for one
// armed run. It is created via NewWatcher and started via Watch. A single
// Watcher is used for one arm run; create a new one for each new arm.
//
// It is safe to call SetSignalFn and SetHMACKey before calling Watch.
// After Watch is called, these setters must not be called concurrently.
type Watcher struct {
	cfg     Config
	reg     *approve.Registry
	audit   auditAppender
	notify  notifyClient
	now     func() time.Time
	sigFn   signalFn
	hmacKey []byte

	// hashStream receives closure hashes from the gate observer callback. It is
	// created in NewWatcher and registered with the gated runner immediately so
	// that hashes pushed before Watch() is called are buffered and not lost.
	// Buffered at max(windowSize, 64) to absorb bursts.
	hashStream chan [32]byte

	// startTime is the arm time recorded at NewWatcher — used by Watch to compute
	// wall-clock elapsed. Capturing it here (rather than inside Watch) ensures the
	// elapsed measurement is not affected by goroutine scheduling delay between
	// NewWatcher and Watch.
	startTime time.Time

	// lastReqID holds the most recently opened approve request ID.
	// Protected by lastReqMu. Used by tests via LastRequestID().
	lastReqMu sync.Mutex
	lastReqID string
}

// NewWatcher returns a new Watcher. gated may be nil (loop detection disabled).
// If now is nil, time.Now is used. The signalFn defaults to syscall.Kill(-pgid, sig).
//
// The gate observer is registered immediately in NewWatcher (not deferred to
// Watch) so that hashes produced between NewWatcher and Watch are buffered and
// not lost. This eliminates the observer-registration race in tests and production.
func NewWatcher(
	cfg Config,
	reg *approve.Registry,
	aud auditAppender,
	notify notifyClient,
	gated gatedObserver,
	now func() time.Time,
) *Watcher {
	if now == nil {
		now = time.Now
	}

	// Buffer size: at least the loop window (so we don't drop hashes during a
	// burst of execs) or 64, whichever is larger.
	bufSize := cfg.resolvedLoopWindow()
	if bufSize < 64 {
		bufSize = 64
	}
	hashStream := make(chan [32]byte, bufSize)

	w := &Watcher{
		cfg:        cfg,
		reg:        reg,
		audit:      aud,
		notify:     notify,
		now:        now,
		sigFn:      defaultSignalFn,
		hashStream: hashStream,
		startTime:  now(), // captured at arm time, not at Watch-goroutine start
	}

	// Register the observer immediately. Hashes are queued in hashStream and
	// processed by Watch when it starts its select loop (T-27-17: never block).
	if gated != nil {
		gated.SetObserver(func(hash [32]byte) {
			select {
			case hashStream <- hash:
			default:
				// hashStream full: drop hash (backpressure — observer must not block).
			}
		})
	}

	return w
}

// SetSignalFn replaces the signal sender with a test double. Must be called
// before Watch; not safe for concurrent use with Watch.
func (w *Watcher) SetSignalFn(fn func(pgid int, sig syscall.Signal) error) {
	w.sigFn = fn
}

// SetHMACKey sets the HMAC key used to sign approve/deny capability URLs.
// Required for ladder mode; ignored in shadow mode. Must be called before Watch.
func (w *Watcher) SetHMACKey(key []byte) {
	w.hmacKey = key
}

// LastRequestID returns the most recently opened approve request ID.
// Used by tests to simulate phone Approve/Deny taps via registry.Resolve.
func (w *Watcher) LastRequestID() string {
	w.lastReqMu.Lock()
	defer w.lastReqMu.Unlock()
	return w.lastReqID
}

func (w *Watcher) setLastRequestID(id string) {
	w.lastReqMu.Lock()
	w.lastReqID = id
	w.lastReqMu.Unlock()
}

// Watch runs the budget observation loop in the current goroutine until ctx
// is cancelled or the armed process signals completion. It always calls
// bindCastAudit on return (even on error), so the cast sha256 is bound into
// the audit chain (KILL-05).
//
// pgid must be > 0 (Pitfall 3: negative pgid double-negates and signals wrong group).
// castPath is the asciinema cast file path (may not yet exist when Watch starts).
// stashSHA and headSHA are the arm-time git snapshot shas (informational; unused in this package).
func (w *Watcher) Watch(ctx context.Context, pgid int, castPath, stashSHA, headSHA string) error {
	// T-31-03: assert pgid positive before any syscall.Kill(-pgid, sig) call.
	if pgid <= 0 {
		return fmt.Errorf("budget: Watch: pgid must be > 0, got %d", pgid)
	}

	_ = stashSHA // used by cmd_arm.go for rollback; stored here for future use
	_ = headSHA  // used by cmd_arm.go for rollback; stored here for future use

	// Build the loop detector with resolved config values.
	// loopDetector is NOT goroutine-safe; it is touched only inside the Watch
	// goroutine via w.hashStream (set up in NewWatcher).
	ld := &loopDetector{
		window:     make([]string, w.cfg.resolvedLoopWindow()),
		windowSize: w.cfg.resolvedLoopWindow(),
		tripN:      w.cfg.resolvedLoopN(),
	}

	// T-31-05: loopTripped is a buffered channel (size 1). If Watch hasn't
	// drained the previous trip, a concurrent loop signal is dropped — correct:
	// single trip per threshold-check cycle.
	loopTripped := make(chan struct{}, 1)

	// Ensure audit binding fires even if Watch returns early.
	defer w.bindCastAudit(castPath)

	// Wall-clock observation: WallClock == 0 means disabled (caller did not
	// configure it). When > 0, a real-time ticker fires every 5ms; on each tick
	// we check w.now() - w.startTime >= WallClock. Tests inject a fake now() and
	// advance it; the next tick detects the threshold immediately without sleeping.
	// startTime is captured at NewWatcher (arm time), not here, to avoid
	// goroutine-scheduling jitter between NewWatcher and Watch.
	wallClock := w.cfg.WallClock
	startTime := w.startTime

	var clockTicker *time.Ticker
	if wallClock > 0 {
		clockTicker = time.NewTicker(5 * time.Millisecond)
		defer clockTicker.Stop()
	}

	slog.Info("budget: Watch started",
		"pgid", pgid,
		"wall_clock", wallClock,
		"loop_n", ld.tripN,
		"loop_window", ld.windowSize,
		"ladder", w.cfg.Ladder,
		"cast_path", castPath,
	)

	for {
		select {
		case <-ctx.Done():
			slog.Info("budget: Watch context done", "pgid", pgid, "err", ctx.Err())
			return ctx.Err()

		case hash := <-w.hashStream:
			// Process hash in Watch goroutine — loopDetector is single-goroutine here.
			if ld.push(hash) {
				select {
				case loopTripped <- struct{}{}:
				default:
					// Already a pending trip in the channel — drop (T-31-05).
				}
			}

		case <-func() <-chan time.Time {
			if clockTicker != nil {
				return clockTicker.C
			}
			return nil
		}():
			// Poll the injected clock to detect wall-clock threshold.
			elapsed := w.now().Sub(startTime)
			if elapsed >= wallClock {
				slog.Info("budget: wall-clock threshold tripped", "pgid", pgid, "elapsed", elapsed)
				w.tripThreshold(ctx, pgid, "wall_clock")
				// Reset startTime so the threshold can re-arm after resume.
				startTime = w.now()
			}

		case <-loopTripped:
			slog.Info("budget: loop-detection threshold tripped", "pgid", pgid)
			w.tripThreshold(ctx, pgid, "loop")
		}
	}
}

// tripThreshold handles a threshold trip for the given reason ("wall_clock" or "loop").
// In shadow mode: fires a notification only.
// In ladder mode: sends SIGSTOP, opens an approve request, and waits for phone response.
func (w *Watcher) tripThreshold(ctx context.Context, pgid int, reason string) {
	if !w.cfg.Ladder {
		// Shadow mode: notify only, no signal (D-05).
		if err := w.notify.SendAgentStopped(ctx, reason); err != nil {
			slog.Warn("budget: SendAgentStopped failed (shadow)", "reason", reason, "err", err)
		}
		return
	}

	// Ladder mode: SIGSTOP → approve → SIGCONT or kill (D-06).
	w.runLadder(ctx, pgid, reason)
}

// runLadder implements the escalation ladder (KILL-02, D-06):
//  1. Send SIGSTOP to the process group.
//  2. Open an approve request and notify the phone.
//  3. Wait for phone response; on timeout re-notify and stay frozen (D-06: never auto-decide).
//  4. On Approve: send SIGCONT and return (watcher re-arms).
//  5. On Deny: send SIGTERM → wait KillGrace → SIGKILL.
//
// Safety net (T-31-06): a deferred SIGCONT is sent if the function returns
// without having sent SIGKILL — ensures the process is never left frozen.
// Complexity is kept low by delegating to openApproveReq and killLadder.
func (w *Watcher) runLadder(ctx context.Context, pgid int, reason string) {
	// Defense-in-depth fail-OPEN guard (T-31-21): if ladder mode was enabled
	// but no approve registry was wired, we cannot ask the phone. Sending the
	// process group SIGSTOP here would freeze the agent with no way to resume
	// (the prior shipped bug, 31-VERIFICATION.md gap #1). Security posture is
	// "fail open on kill-switch misconfiguration": send SIGCONT and return
	// BEFORE any SIGSTOP, so the agent is never frozen in the first place. This
	// must run ahead of the killed/safety-net defer below — the defer only
	// un-freezes AFTER SIGSTOP, and a nil-receiver panic in openApproveReq would
	// bypass it entirely (CLAUDE.md "no panics in normal control flow").
	if w.reg == nil {
		slog.Error("budget: ladder enabled but no approve registry wired — cannot ask phone; sending SIGCONT (fail open to avoid orphaning the agent)",
			"pgid", pgid, "reason", reason)
		if err := w.sigFn(pgid, syscall.SIGCONT); err != nil {
			slog.Warn("budget: fail-open SIGCONT (nil registry) failed", "pgid", pgid, "err", err)
		}
		return
	}

	// killed tracks whether we intentionally disposed of the process.
	// The safety-net defer sends SIGCONT only when killed==false.
	killed := false
	defer func() {
		if !killed {
			// Safety net (T-31-06): un-freeze the process on unexpected exit.
			if err := w.sigFn(pgid, syscall.SIGCONT); err != nil {
				slog.Warn("budget: safety-net SIGCONT failed", "pgid", pgid, "err", err)
			}
		}
	}()

	// 1. SIGSTOP the whole process group (before opening the approve request so
	// the process is frozen before the phone URL is minted — security ordering).
	if err := w.sigFn(pgid, syscall.SIGSTOP); err != nil {
		slog.Warn("budget: SIGSTOP failed", "pgid", pgid, "err", err)
	}

	// Stable closure hash for this ladder invocation (bound into the APPR request).
	armClosureHex := fmt.Sprintf("budget-ladder-pgid%d-%s", pgid, reason)
	var armClosure [32]byte
	copy(armClosure[:], []byte(armClosureHex))

	// 2. Open the initial approve request.
	requestID, openOK := w.openApproveReq(ctx, pgid, armClosure, reason)
	if !openOK {
		// openApproveReq already sent SIGCONT and logged the error.
		killed = true
		return
	}

	// 3–5. Wait loop: re-notify on timeout, act on phone answer.
	approvalTimeout := w.cfg.resolvedApprovalTimeout()
	for {
		approveCtx, approveCancel := context.WithTimeout(ctx, approvalTimeout)
		res, waitErr := w.reg.WaitByID(approveCtx, requestID, false /*hasTTY=false*/)
		// Capture deadline state BEFORE approveCancel() — after cancel,
		// approveCtx.Err() always returns context.Canceled (T-31-07).
		approveTimedOut := approveCtx.Err() != nil
		approveCancel()

		if ctx.Err() != nil {
			// Parent context cancelled — armed process ended.
			return
		}

		if errors.Is(waitErr, approve.ErrDenied) && approveTimedOut {
			// Timeout with no phone answer: stay frozen + re-notify (D-06).
			requestID = w.reNotify(ctx, pgid, armClosure, reason)
			continue
		}

		if waitErr == nil && res.Approved {
			// Phone tapped Resume → SIGCONT, watcher re-arms.
			slog.Info("budget: Resume approved — sending SIGCONT", "pgid", pgid)
			if err := w.sigFn(pgid, syscall.SIGCONT); err != nil {
				slog.Warn("budget: SIGCONT after resume failed", "pgid", pgid, "err", err)
			}
			killed = true
			return
		}

		// Real phone Deny tap → kill ladder (D-07).
		w.killLadder(pgid)
		killed = true
		return
	}
}

// openApproveReq builds HMAC sigs, opens an approve request in the registry,
// stores the request ID, and sends the initial KindAgentStopped notification.
// Returns (requestID, true) on success, ("", false) on registry open failure
// (in which case it sends SIGCONT itself so the process is not left frozen).
func (w *Watcher) openApproveReq(ctx context.Context, pgid int, armClosure [32]byte, reason string) (string, bool) {
	requestID := notifyv2.NewMsgID()
	approveSig, denySig := w.buildHMACSigs(requestID, armClosure)

	_, err := w.reg.OpenWithDenySig(requestID, armClosure, approve.TierSensitive, approveSig, denySig)
	if err != nil {
		slog.Warn("budget: OpenWithDenySig failed", "pgid", pgid, "err", err)
		if cerr := w.sigFn(pgid, syscall.SIGCONT); cerr != nil {
			slog.Warn("budget: SIGCONT on open-fail failed", "pgid", pgid, "err", cerr)
		}
		return "", false
	}
	w.setLastRequestID(requestID)

	if err := w.notify.SendAgentStopped(ctx, reason); err != nil {
		slog.Warn("budget: SendAgentStopped failed (ladder)", "reason", reason, "err", err)
	}
	return requestID, true
}

// reNotify opens a fresh approve request and fires a re-notify (D-06).
// Returns the new requestID for the next WaitByID call.
func (w *Watcher) reNotify(ctx context.Context, pgid int, armClosure [32]byte, reason string) string {
	newID := notifyv2.NewMsgID()
	approveSig, denySig := w.buildHMACSigs(newID, armClosure)
	_, openErr := w.reg.OpenWithDenySig(newID, armClosure, approve.TierSensitive, approveSig, denySig)
	if openErr != nil {
		slog.Warn("budget: re-notify OpenWithDenySig failed", "pgid", pgid, "err", openErr)
	} else {
		w.setLastRequestID(newID)
	}
	if notifyErr := w.notify.SendAgentStopped(ctx, reason+"/re-notify"); notifyErr != nil {
		slog.Warn("budget: re-notify SendAgentStopped failed", "reason", reason, "err", notifyErr)
	}
	slog.Info("budget: no phone answer — staying frozen, re-notified (D-06)", "pgid", pgid, "reason", reason)
	return newID
}

// killLadder sends SIGTERM then SIGKILL after KillGrace (D-07).
func (w *Watcher) killLadder(pgid int) {
	slog.Info("budget: Kill denied — sending SIGTERM then SIGKILL", "pgid", pgid, "grace", w.cfg.resolvedKillGrace())
	if err := w.sigFn(pgid, syscall.SIGTERM); err != nil {
		slog.Warn("budget: SIGTERM failed", "pgid", pgid, "err", err)
	}
	time.Sleep(w.cfg.resolvedKillGrace())
	if err := w.sigFn(pgid, syscall.SIGKILL); err != nil {
		slog.Warn("budget: SIGKILL failed", "pgid", pgid, "err", err)
	}
}

// buildHMACSigs returns (approveSig, denySig) for the given requestID and
// armClosure. Returns ("", "") when no HMAC key is configured (logs a warning).
func (w *Watcher) buildHMACSigs(requestID string, armClosure [32]byte) (string, string) {
	if len(w.hmacKey) == 0 {
		slog.Warn("budget: HMAC key not set — capability URLs lack integrity signature (D-16 absent)")
		return "", ""
	}
	return approve.SignApproveURL(w.hmacKey, requestID, "approve", armClosure),
		approve.SignApproveURL(w.hmacKey, requestID, "deny", armClosure)
}

// bindCastAudit reads the cast file and binds its sha256 into the audit chain
// via audit.Append("arm-run:end", castPath, castBytes, false). Called deferred
// from Watch so it fires on every exit path (KILL-05, D-10).
//
// If the file cannot be read (never written, recording failed), a sentinel byte
// slice is used so DiffHash is never the well-known sha256(nil) hash (Pitfall 2).
// If the file exceeds 256 MiB (castReadCeiling), it is truncated with a warning
// (T-31-09: DoS via large cast file). Errors are logged with slog.Warn; no panic.
func (w *Watcher) bindCastAudit(castPath string) {
	castBytes, err := w.readCastFile(castPath)
	if appendErr := w.audit.Append("arm-run:end", castPath, castBytes, false); appendErr != nil {
		slog.Warn("budget: audit binding failed", "cast_path", castPath, "err", appendErr)
	}
	_ = err // already handled in readCastFile (sentinel set, warning logged)
}

// readCastFile reads the cast file at castPath, applying the 256 MiB ceiling.
// On error returns a non-nil sentinel byte slice and the error (Pitfall 2).
func (w *Watcher) readCastFile(castPath string) ([]byte, error) {
	fi, err := os.Stat(castPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			slog.Warn("budget: cast file not found — using sentinel for audit binding",
				"cast_path", castPath)
		} else {
			slog.Warn("budget: cannot stat cast file — using sentinel for audit binding",
				"cast_path", castPath, "err", err)
		}
		return []byte("cast-read-error:" + err.Error()), err
	}

	if fi.Size() > castReadCeiling {
		slog.Warn("budget: cast file exceeds ceiling — truncating read for audit binding",
			"cast_path", castPath,
			"size", fi.Size(),
			"ceiling", castReadCeiling,
		)
	}

	raw, err := os.ReadFile(castPath) //nolint:gosec // G304: castPath is operator-controlled (arm time); hashed not executed
	if err != nil {
		slog.Warn("budget: cannot read cast file — using sentinel for audit binding",
			"cast_path", castPath, "err", err)
		return []byte("cast-read-error:" + err.Error()), err
	}

	if len(raw) > castReadCeiling {
		raw = raw[:castReadCeiling]
	}
	return raw, nil
}

// ConfigFrom converts a config.BudgetConfig (YAML-sourced, zero-means-default)
// to a runtime Config with all durations resolved. It is the canonical bridge
// between the install-time YAML representation and the budget watcher's runtime
// Config. Zero values in BudgetConfig map to the compiled-in defaults
// documented on Config (wall-clock 30m, loop 8/20, kill grace 5s).
func ConfigFrom(b config.BudgetConfig) Config {
	wallClock := time.Duration(b.WallClockMinutes) * time.Minute
	if b.WallClockMinutes == 0 {
		wallClock = 30 * time.Minute // D-04 shadow-mode default
	}
	return Config{
		WallClock:       wallClock,
		LoopN:           b.LoopN,
		LoopWindow:      b.LoopWindow,
		Ladder:          b.Ladder,
		KillGrace:       time.Duration(b.KillGraceSeconds) * time.Second,
		ApprovalTimeout: 0, // use package default (2 min)
	}
}
