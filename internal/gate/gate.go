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
	"hash"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"

	"github.com/abysslink/abysslink/internal/shell"
)

// maxScriptContentBytes caps the args[0]-as-script content read folded into
// the D-39 closure hash. Larger files are silently excluded so observe mode
// never slows an exec materially (T-27-17).
const maxScriptContentBytes = 4 * 1024 * 1024 // 4 MiB

// Gated is the observe-only shell.Runner decorator (D-38). Each method
// records the exec — binary name plus argv/closure sha256 hashes, never raw
// argv — increments an atomic counter, then delegates verbatim to the inner
// Runner with zero behavior change.
type Gated struct {
	inner shell.Runner
	log   *slog.Logger
	count atomic.Uint64
}

var _ shell.Runner = (*Gated)(nil)

// Option configures a Gated at construction time.
type Option func(*Gated)

// WithLogger overrides the logger used for exec records (default
// slog.Default()). It exists as a test seam for log-hygiene assertions.
func WithLogger(l *slog.Logger) Option {
	return func(g *Gated) { g.log = l }
}

// New returns a Gated decorator around inner. The decorator is observe-only
// in v4.0.0 Phase 27: it never blocks, retries, mutates, or wraps — Phase 30
// flips it to enforcing without touching any module.
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

// Run records the exec, then delegates verbatim to the inner Runner.
func (g *Gated) Run(ctx context.Context, name string, args ...string) (shell.Result, error) {
	g.record("Run", name, args)
	return g.inner.Run(ctx, name, args...)
}

// RunWithStdin records the exec, then delegates verbatim to the inner Runner.
// The stdin reader is passed through untouched — its content (often a secret)
// is never read or hashed by the gate.
func (g *Gated) RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (shell.Result, error) {
	g.record("RunWithStdin", name, args)
	return g.inner.RunWithStdin(ctx, stdin, name, args...)
}

// RunInteractive records the exec, then delegates verbatim to the inner Runner.
func (g *Gated) RunInteractive(ctx context.Context, name string, args ...string) error {
	g.record("RunInteractive", name, args)
	return g.inner.RunInteractive(ctx, name, args...)
}

// RunWithEnv records the exec, then delegates verbatim to the inner Runner.
// Env values are not hashed or logged — they can carry secrets.
func (g *Gated) RunWithEnv(ctx context.Context, env map[string]string, name string, args ...string) (shell.Result, error) {
	g.record("RunWithEnv", name, args)
	return g.inner.RunWithEnv(ctx, env, name, args...)
}

// RunStream records the exec, then delegates verbatim to the inner Runner,
// returning the inner *shell.Stream handle untouched.
func (g *Gated) RunStream(ctx context.Context, name string, args ...string) (*shell.Stream, error) {
	g.record("RunStream", name, args)
	return g.inner.RunStream(ctx, name, args...)
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
