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
	"fmt"
	"io"

	"github.com/abysslink/abysslink/internal/shell"
)

// Sentinel is the shell.Runner decorator that feeds every observed exec's argv
// to the detection engine BEFORE delegating verbatim to the inner runner. It is
// placed INSIDE the gate (gate.New(sentinel.New(base, eng))) so it never
// touches the single-slot gate observer that budget.Watcher owns and the outer
// *gate.Gated stays the runner returned/injected everywhere (budget's
// SetObserver binding, gated.Count, and arm_cmd's setObserver assertion all
// still resolve to *Gated, unchanged).
//
// Every Run* method (1) best-effort feeds argv to the engine — the engine
// recovers panics internally and never blocks, fails, or slows the exec
// (T-27-17), and (2) delegates VERBATIM to the inner runner. The detector never
// returns an error that fails or blocks the delegated exec. Detections surface
// via log/slog + internal/audit only.
//
// A nil engine (or a disabled one) makes the decorator a pure, cheap
// pass-through — the engine's observe method is nil-receiver safe.
type Sentinel struct {
	inner shell.Runner
	eng   *Engine
}

// New wraps inner with the detection engine eng. eng may be nil (pure
// pass-through). The returned *Sentinel is itself a shell.Runner and forwards
// the three optional capability interfaces (DirRunner, ArmedRunner,
// ArmedMinimalRunner) by type-asserting inner and delegating, so an outer
// *gate.Gated wrapping this decorator can still reach ssh-keygen -K (HWK-01)
// and the armed-agent spawn path.
func New(inner shell.Runner, eng *Engine) *Sentinel {
	return &Sentinel{inner: inner, eng: eng}
}

// Compile guards: the decorator MUST satisfy the Runner interface plus the
// three optional capabilities, or an outer *gate.Gated's type assertions
// (gate.go RunInteractiveDir/RunArmed/RunArmedMinimal) fail and arming + HWK-01
// break fail-closed. Mirrors gate.go's own compile guards.
var (
	_ shell.Runner             = (*Sentinel)(nil)
	_ shell.DirRunner          = (*Sentinel)(nil)
	_ shell.ArmedRunner        = (*Sentinel)(nil)
	_ shell.ArmedMinimalRunner = (*Sentinel)(nil)
)

// Run observes then delegates.
func (s *Sentinel) Run(ctx context.Context, name string, args ...string) (shell.Result, error) {
	s.eng.observe(ctx, "Run", name, args)
	return s.inner.Run(ctx, name, args...)
}

// RunWithStdin observes then delegates. The stdin reader is passed through
// untouched — its content (often a secret) is never read or inspected.
func (s *Sentinel) RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (shell.Result, error) {
	s.eng.observe(ctx, "RunWithStdin", name, args)
	return s.inner.RunWithStdin(ctx, stdin, name, args...)
}

// RunInteractive observes then delegates.
func (s *Sentinel) RunInteractive(ctx context.Context, name string, args ...string) error {
	s.eng.observe(ctx, "RunInteractive", name, args)
	return s.inner.RunInteractive(ctx, name, args...)
}

// RunWithEnv observes then delegates. Env values are not inspected — they can
// carry secrets.
func (s *Sentinel) RunWithEnv(ctx context.Context, env map[string]string, name string, args ...string) (shell.Result, error) {
	s.eng.observe(ctx, "RunWithEnv", name, args)
	return s.inner.RunWithEnv(ctx, env, name, args...)
}

// RunStream observes then delegates, returning the inner *shell.Stream handle
// untouched.
func (s *Sentinel) RunStream(ctx context.Context, name string, args ...string) (*shell.Stream, error) {
	s.eng.observe(ctx, "RunStream", name, args)
	return s.inner.RunStream(ctx, name, args...)
}

// RunInteractiveDir observes then delegates to the inner runner's
// shell.DirRunner capability (ssh-keygen -K, HWK-01). An inner runner without
// the capability is refused with an error (fail closed), mirroring Gated.
func (s *Sentinel) RunInteractiveDir(ctx context.Context, dir, name string, args ...string) error {
	s.eng.observe(ctx, "RunInteractiveDir", name, args)
	dr, ok := s.inner.(shell.DirRunner)
	if !ok {
		return fmt.Errorf("sentinel: inner runner %T does not implement DirRunner — cannot run in a controlled working directory", s.inner)
	}
	return dr.RunInteractiveDir(ctx, dir, name, args...)
}

// RunArmed observes then delegates to the inner runner's shell.ArmedRunner
// capability. Seeing the armed spawn is a FEATURE for a danger detector (the
// armed agent is the untrusted party), so it feeds the engine too.
func (s *Sentinel) RunArmed(ctx context.Context, name string, args ...string) (*shell.ArmedHandle, error) {
	s.eng.observe(ctx, "RunArmed", name, args)
	ar, ok := s.inner.(shell.ArmedRunner)
	if !ok {
		return nil, fmt.Errorf("sentinel: inner runner %T does not implement ArmedRunner — cannot arm process", s.inner)
	}
	return ar.RunArmed(ctx, name, args...)
}

// RunArmedMinimal observes then delegates to the inner runner's
// shell.ArmedMinimalRunner capability, mirroring RunArmed.
func (s *Sentinel) RunArmedMinimal(ctx context.Context, name string, args ...string) (*shell.ArmedHandle, error) {
	s.eng.observe(ctx, "RunArmedMinimal", name, args)
	ar, ok := s.inner.(shell.ArmedMinimalRunner)
	if !ok {
		return nil, fmt.Errorf("sentinel: inner runner %T does not implement ArmedMinimalRunner — cannot arm process with minimized env", s.inner)
	}
	return ar.RunArmedMinimal(ctx, name, args...)
}
