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

package gate

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/shell"
)

// ErrClosureHashMismatch is returned by enforcing-mode Run methods when the
// approved closure hash does not match the hash recomputed at exec time.
// This structurally closes the TOCTOU window between approval and execution
// (APPR-01, D-02).
var ErrClosureHashMismatch = errors.New("gate: closure hash mismatch — exec refused (TOCTOU)")

// ErrApprovalRequired is returned by enforcing-mode Run methods when no
// ApprovalToken is present in ctx and the exec requires approval (APPR-05).
var ErrApprovalRequired = errors.New("gate: approval token required in enforcing mode")

// maxScriptContentBytes caps the args[0]-as-script content read folded into
// the D-39 closure hash. Larger files are silently excluded so observe mode
// never slows an exec materially (T-27-17).
const maxScriptContentBytes = 4 * 1024 * 1024 // 4 MiB

// Gated is the shell.Runner decorator (D-38). In the default shadow mode it
// records every exec — binary name plus argv/closure sha256 hashes, never raw
// argv — increments an atomic counter, then delegates verbatim to the inner
// Runner with zero behavior change.
//
// In enforcing mode (opt-in via WithEnforcing) each Run method additionally
// checks for an ApprovalToken in ctx and re-verifies the closure hash before
// delegating. See WithEnforcing for the D-40 structural-bypass invariant.
type Gated struct {
	inner     shell.Runner
	log       *slog.Logger
	count     atomic.Uint64
	enforcing bool              // when true, Run checks ctx for ApprovalToken and re-verifies closure hash; default false per D-04
	registry  *approve.Registry // daemon-side approve registry client; only meaningful when enforcing==true; never set on the daemon-internal runner (D-40 structural bypass)

	// mu protects observer. SetObserver is called once at arm time;
	// record() reads it on every exec. A mutex shard is the simplest
	// correct choice: observer is set rarely and read frequently.
	mu       sync.Mutex
	observer func([32]byte) // non-nil when a budget.Watcher has registered (KILL-01, D-03)
}

// ctxKey is the unexported context-value key for ApprovalToken. The
// package-private type prevents cross-package collision with other context
// keys even if they use the same underlying type.
type ctxKey struct{}

// WithApprovalToken returns a new context carrying tok. The gate's Run methods
// extract it via approvalTokenFromCtx to perform TOCTOU re-verification.
func WithApprovalToken(ctx context.Context, tok *approve.ApprovalToken) context.Context {
	return context.WithValue(ctx, ctxKey{}, tok)
}

// approvalTokenFromCtx retrieves the ApprovalToken stored by WithApprovalToken.
// Returns (nil, false) when no token is present.
func approvalTokenFromCtx(ctx context.Context) (*approve.ApprovalToken, bool) {
	tok, ok := ctx.Value(ctxKey{}).(*approve.ApprovalToken)
	return tok, ok && tok != nil
}

var _ shell.Runner = (*Gated)(nil)

// The decorator must never strip the optional working-directory capability
// off the production composition root (gate.New(&shell.ExecRunner{})): the
// hardware-key enclave enrollment (`ssh-keygen -K`, HWK-01) type-asserts
// shell.DirRunner and refuses fail-closed without it.
var _ shell.DirRunner = (*Gated)(nil)

// Option configures a Gated at construction time.
type Option func(*Gated)

// WithLogger overrides the logger used for exec records (default
// slog.Default()). It exists as a test seam for log-hygiene assertions.
func WithLogger(l *slog.Logger) Option {
	return func(g *Gated) { g.log = l }
}

// WithEnforcing flips the Gated decorator from observe-only to enforcing mode.
// In enforcing mode, every Run/RunWithStdin/RunInteractive/RunInteractiveDir/
// RunWithEnv/RunStream call checks for an ApprovalToken in ctx and refuses
// execs that lack one.
// When a token is present the closure hash is re-verified (APPR-01 TOCTOU
// structurally closed).
//
// CRITICAL INVARIANT (D-40): The daemon-internal runner (used for tmux -CC,
// probes, etc.) is constructed with plain New(inner) — never WithEnforcing.
// This is the structural self-deadlock bypass: visible in the dep graph, not
// runtime-toggleable. WithEnforcing is only called on the exec-gate runner
// that wraps user-initiated execs (cmd/abysslinkd composition root).
func WithEnforcing(registry *approve.Registry) Option {
	return func(g *Gated) {
		g.enforcing = true
		g.registry = registry
	}
}

// New returns a Gated decorator around inner. The decorator is observe-only
// (shadow mode) unless WithEnforcing is supplied. Shadow mode never blocks,
// retries, mutates, or wraps — Phase 30 added enforcing mode for user-facing
// exec paths.
func New(inner shell.Runner, opts ...Option) *Gated {
	g := &Gated{inner: inner, log: slog.Default()}
	for _, o := range opts {
		o(g)
	}
	return g
}

// Count returns the number of execs observed so far. It is surfaced on the
// daemon's GET /status as gate_execs_observed, proving the seam intercepts
// every module/consumer exec before Phase 30 makes it load-bearing.
func (g *Gated) Count() uint64 { return g.count.Load() }

// SetObserver registers a non-blocking callback called by record() with the
// computed closure hash after each exec is observed. It replaces any previous
// callback. A nil fn deregisters. The callback must not block; panics are
// recovered silently (same T-27-17 rule: the observer must never fail or block
// an exec). Used by budget.Watcher for loop detection (KILL-01, D-03).
func (g *Gated) SetObserver(fn func([32]byte)) {
	g.mu.Lock()
	g.observer = fn
	g.mu.Unlock()
}

// requiresApproval reports whether an exec in enforcing mode must carry an
// ApprovalToken. Phase 30: all execs require approval in enforcing mode.
// Phase 31 will add per-action tier allowlisting.
func (g *Gated) requiresApproval(_ string, _ []string) bool {
	return true
}

// checkEnforcing performs the enforcing-mode gate check for the named exec.
// It is called after record() so the counter is always incremented first.
// Returns nil when the exec is allowed to proceed; returns ErrApprovalRequired
// or ErrClosureHashMismatch when the exec must be refused.
func (g *Gated) checkEnforcing(ctx context.Context, name string, args []string) error {
	if !g.enforcing {
		return nil
	}
	tok, hasTok := approvalTokenFromCtx(ctx)
	if hasTok {
		// Re-verify closure hash (TOCTOU closure per D-02/APPR-01).
		current := closureHash(name, args)
		if current != tok.ClosureHash {
			slog.Warn("gate: closure hash mismatch — exec refused (TOCTOU)",
				"approved_prefix", hex.EncodeToString(tok.ClosureHash[:8]),
				"current_prefix", hex.EncodeToString(current[:8]),
			)
			return ErrClosureHashMismatch
		}
		// Hash matches — token was already CAS-resolved in the registry
		// (single-use: this exec proceeds).
		return nil
	}
	// No token in context.
	if g.requiresApproval(name, args) {
		return ErrApprovalRequired
	}
	// Exec does not require approval in enforcing mode — pass through.
	return nil
}

// Run records the exec, enforces the approval gate when in enforcing mode,
// then delegates to the inner Runner.
func (g *Gated) Run(ctx context.Context, name string, args ...string) (shell.Result, error) {
	g.record("Run", name, args)
	if err := g.checkEnforcing(ctx, name, args); err != nil {
		return shell.Result{}, err
	}
	return g.inner.Run(ctx, name, args...)
}

// RunWithStdin records the exec, enforces the gate, then delegates. The stdin
// reader is passed through untouched — its content (often a secret) is never
// read or hashed by the gate.
func (g *Gated) RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (shell.Result, error) {
	g.record("RunWithStdin", name, args)
	if err := g.checkEnforcing(ctx, name, args); err != nil {
		return shell.Result{}, err
	}
	return g.inner.RunWithStdin(ctx, stdin, name, args...)
}

// RunInteractive records the exec, enforces the gate, then delegates.
func (g *Gated) RunInteractive(ctx context.Context, name string, args ...string) error {
	g.record("RunInteractive", name, args)
	if err := g.checkEnforcing(ctx, name, args); err != nil {
		return err
	}
	return g.inner.RunInteractive(ctx, name, args...)
}

// RunInteractiveDir records the exec, enforces the gate, then delegates to the
// inner runner's shell.DirRunner capability (the optional working-directory
// interface `ssh-keygen -K` needs — HWK-01). The passthrough exists because a
// decorator without it silently STRIPS the capability off shell.ExecRunner,
// making the enclave enrollment structurally unreachable in the shipped
// binary. An inner runner that does not implement shell.DirRunner is refused
// with an error (fail closed — never worked around by chdir'ing the parent
// process), mirroring RunArmed's inner type assertion.
func (g *Gated) RunInteractiveDir(ctx context.Context, dir, name string, args ...string) error {
	g.record("RunInteractiveDir", name, args)
	if err := g.checkEnforcing(ctx, name, args); err != nil {
		return err
	}
	dr, ok := g.inner.(shell.DirRunner)
	if !ok {
		return fmt.Errorf("gate: inner runner %T does not implement DirRunner — cannot run in a controlled working directory", g.inner)
	}
	return dr.RunInteractiveDir(ctx, dir, name, args...)
}

// RunWithEnv records the exec, enforces the gate, then delegates. Env values
// are not hashed or logged — they can carry secrets.
func (g *Gated) RunWithEnv(ctx context.Context, env map[string]string, name string, args ...string) (shell.Result, error) {
	g.record("RunWithEnv", name, args)
	if err := g.checkEnforcing(ctx, name, args); err != nil {
		return shell.Result{}, err
	}
	return g.inner.RunWithEnv(ctx, env, name, args...)
}

// RunStream records the exec, enforces the gate, then delegates, returning the
// inner *shell.Stream handle untouched.
func (g *Gated) RunStream(ctx context.Context, name string, args ...string) (*shell.Stream, error) {
	g.record("RunStream", name, args)
	if err := g.checkEnforcing(ctx, name, args); err != nil {
		return nil, err
	}
	return g.inner.RunStream(ctx, name, args...)
}

// RunArmed delegates to the inner runner if it implements shell.ArmedRunner.
// This allows gate.Gated to satisfy shell.ArmedRunner when its inner runner is
// a *shell.ExecRunner (the production composition root). The gate deliberately
// does NOT enforce approval or record the armed spawn: RunArmed starts a
// long-running process monitored by the budget watcher, not a discrete tool
// call observable as a single exec event (D-01a, KILL-03).
func (g *Gated) RunArmed(ctx context.Context, name string, args ...string) (*shell.ArmedHandle, error) {
	ar, ok := g.inner.(shell.ArmedRunner)
	if !ok {
		return nil, fmt.Errorf("gate: inner runner %T does not implement ArmedRunner — cannot arm process", g.inner)
	}
	return ar.RunArmed(ctx, name, args...)
}

// RunArmedMinimal delegates to the inner runner if it implements
// shell.ArmedMinimalRunner, mirroring RunArmed. This preserves the D-38
// decoration chain so the production composition root (Gated wrapping
// *shell.ExecRunner) can reach the B10 env-minimized armed spawn when the
// operator opts in (Budget.MinimizeAgentEnv). Like RunArmed it deliberately does
// NOT enforce approval or record the spawn: the armed process is a long-running,
// budget-watcher-monitored run, not a discrete exec event (D-01a, KILL-03).
func (g *Gated) RunArmedMinimal(ctx context.Context, name string, args ...string) (*shell.ArmedHandle, error) {
	ar, ok := g.inner.(shell.ArmedMinimalRunner)
	if !ok {
		return nil, fmt.Errorf("gate: inner runner %T does not implement ArmedMinimalRunner — cannot arm process with minimized env", g.inner)
	}
	return ar.RunArmedMinimal(ctx, name, args...)
}

// record emits one slog debug line per observed exec carrying the method,
// binary name, and the first 8 bytes (hex) of the argv and closure sha256
// hashes — NEVER raw argv, which can carry user paths, hostnames, and
// tokens-by-accident (D-38, T-27-14). Errors inside record (path resolution,
// cwd, script read) degrade to fallback values and never propagate to the
// exec: observe mode must never fail or block a command (T-27-17).
func (g *Gated) record(method, name string, args []string) {
	argv := argvHash(name, args)
	closure := closureHash(name, args)
	g.log.Debug("gate: exec observed",
		"method", method,
		"binary", name,
		"argv_sha256", hex.EncodeToString(argv[:8]),
		"closure_sha256", hex.EncodeToString(closure[:8]),
	)
	g.count.Add(1)

	// Notify the observer (budget.Watcher loop-detection tap, KILL-01 D-03).
	// Read under lock, call outside lock so the observer cannot deadlock on g.mu.
	// Panics are recovered: the observer must never fail or block an exec (T-27-17).
	g.mu.Lock()
	fn := g.observer
	g.mu.Unlock()
	if fn != nil {
		func() {
			defer func() { _ = recover() }()
			fn(closure)
		}()
	}
}

// argvHash is sha256 over name and args joined with a NUL separator.
func argvHash(name string, args []string) [32]byte {
	joined := strings.Join(append([]string{name}, args...), "\x00")
	return sha256.Sum256([]byte(joined))
}

// closureHash is the D-39 execution-closure hash: sha256 over length-prefixed
// fields so field boundaries are unambiguous —
//
//  1. the resolved binary path (shell.ResolvePath; falls back to the bare
//     name on resolution error — the gate never imports os/exec),
//  2. the current working directory (empty string on os.Getwd error),
//  3. each argument in order,
//  4. the sha256 of args[0]'s content when args[0] names an existing readable
//     regular file of at most maxScriptContentBytes (the script-content leg;
//     skipped silently otherwise).
//
// Phase 30's TOCTOU research inherits this function already exercised across
// every real exec path; known instability surfaces (PATH/cwd sensitivity,
// the 4 MiB cap, hash-time vs exec-time reads) are documented in the plan
// SUMMARY for that research gate rather than papered over here.
func closureHash(name string, args []string) [32]byte {
	h := sha256.New()

	resolved, err := shell.ResolvePath(name)
	if err != nil {
		resolved = name // fallback: bare name (record never fails the exec)
	}
	writeField(h, []byte(resolved))

	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	writeField(h, []byte(cwd))

	for _, a := range args {
		writeField(h, []byte(a))
	}

	if sum, ok := scriptContentHash(args); ok {
		writeField(h, sum)
	}

	var out [32]byte
	h.Sum(out[:0])
	return out
}

// writeField writes one length-prefixed field (big-endian uint64 length, then
// the bytes) into h. sha256's Write never returns an error.
func writeField(h hash.Hash, field []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(field)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(field)
}

// ClosureHashOf is an exported wrapper over closureHash for use by cmd_arm.go.
// It computes the D-39 execution-closure hash for the given command and args
// (resolved binary path + length-prefixed argv fields + optional script hash),
// without exposing the internal closureHash function. Used by the arm command
// to compute the arm-time closure hash for APPR request binding (Pitfall 6).
func ClosureHashOf(name string, args []string) [32]byte {
	return closureHash(name, args)
}

// scriptContentHash returns the sha256 of args[0]'s content when args[0]
// names an existing regular file of at most maxScriptContentBytes. Any stat,
// open, or read failure — or an over-cap or non-regular file — returns
// (nil, false) silently: observe mode must never fail or materially slow an
// exec (T-27-17).
func scriptContentHash(args []string) ([]byte, bool) {
	if len(args) == 0 {
		return nil, false
	}
	fi, err := os.Stat(args[0])
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxScriptContentBytes {
		return nil, false
	}
	f, err := os.Open(args[0]) //nolint:gosec // G304: read-only content hashing of the script the caller is about to exec (D-39); content is hashed, never executed, disclosed, or written; capped at 4 MiB
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	ch := sha256.New()
	if _, err := io.Copy(ch, io.LimitReader(f, maxScriptContentBytes)); err != nil {
		return nil, false
	}
	return ch.Sum(nil), true
}
