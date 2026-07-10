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
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/shell"
)

// approveToken is a test alias so test code can construct ApprovalToken
// values without importing internal/approve by a qualified name repeatedly.
type approveToken = approve.ApprovalToken

// fakeInner is a sentinel-returning shell.Runner: every method returns the
// exact configured Result/Stream/error so pass-through fidelity can assert
// identity, not just equivalence. Safe for concurrent use.
type fakeInner struct {
	mu      sync.Mutex
	res     shell.Result
	err     error
	stream  *shell.Stream
	methods []string
}

var _ shell.Runner = (*fakeInner)(nil)

func (f *fakeInner) note(m string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, m)
}

func (f *fakeInner) Run(_ context.Context, _ string, _ ...string) (shell.Result, error) {
	f.note("Run")
	return f.res, f.err
}

func (f *fakeInner) RunWithStdin(_ context.Context, _ io.Reader, _ string, _ ...string) (shell.Result, error) {
	f.note("RunWithStdin")
	return f.res, f.err
}

func (f *fakeInner) RunInteractive(_ context.Context, _ string, _ ...string) error {
	f.note("RunInteractive")
	return f.err
}

func (f *fakeInner) RunWithEnv(_ context.Context, _ map[string]string, _ string, _ ...string) (shell.Result, error) {
	f.note("RunWithEnv")
	return f.res, f.err
}

func (f *fakeInner) RunStream(_ context.Context, _ string, _ ...string) (*shell.Stream, error) {
	f.note("RunStream")
	return f.stream, f.err
}

func (f *fakeInner) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.methods))
	copy(out, f.methods)
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestGated_PassThroughFidelity proves observe-only delegation on all five
// Runner methods: the Gated decorator returns the IDENTICAL Result, *Stream,
// and error the inner runner produced — no mutation, no wrapping.
func TestGated_PassThroughFidelity(t *testing.T) {
	sentinelRes := shell.Result{Stdout: "captured-out", Stderr: "captured-err", ExitCode: 3}
	sentinelErr := errors.New("inner sentinel failure")
	sentinelStream := &shell.Stream{}
	inner := &fakeInner{res: sentinelRes, err: sentinelErr, stream: sentinelStream}
	g := New(inner, WithLogger(discardLogger()))
	ctx := context.Background()

	t.Run("Run", func(t *testing.T) {
		res, err := g.Run(ctx, "ls", "-la")
		assert.Equal(t, sentinelRes, res)
		assert.Equal(t, sentinelErr, err, "error must be the inner runner's, unwrapped")
	})
	t.Run("RunWithStdin", func(t *testing.T) {
		res, err := g.RunWithStdin(ctx, strings.NewReader("secret"), "ssh-add", "-")
		assert.Equal(t, sentinelRes, res)
		assert.Equal(t, sentinelErr, err)
	})
	t.Run("RunInteractive", func(t *testing.T) {
		err := g.RunInteractive(ctx, "tailscale", "up")
		assert.Equal(t, sentinelErr, err)
	})
	t.Run("RunWithEnv", func(t *testing.T) {
		res, err := g.RunWithEnv(ctx, map[string]string{"GIT_TERMINAL_PROMPT": "0"}, "git", "fetch")
		assert.Equal(t, sentinelRes, res)
		assert.Equal(t, sentinelErr, err)
	})
	t.Run("RunStream", func(t *testing.T) {
		st, err := g.RunStream(ctx, "tmux", "-CC", "attach-session")
		assert.Same(t, sentinelStream, st, "the *shell.Stream handle must be delegated untouched")
		assert.Equal(t, sentinelErr, err)
	})

	assert.Equal(t,
		[]string{"Run", "RunWithStdin", "RunInteractive", "RunWithEnv", "RunStream"},
		inner.seen(), "every call must reach the inner runner exactly once, in order")
}

// TestGated_MockRunnerScriptedReplay wraps the repo-standard MockRunner: the
// scripted Result flows through the gate unchanged and the mock still records
// the actual argv (the gate is invisible to existing test plumbing).
func TestGated_MockRunnerScriptedReplay(t *testing.T) {
	mock := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "scripted", ExitCode: 0}})
	g := New(mock, WithLogger(discardLogger()))

	res, err := g.Run(context.Background(), "tailscale", "status", "--json")
	require.NoError(t, err)
	assert.Equal(t, "scripted", res.Stdout)

	calls := mock.RunCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"tailscale", "status", "--json"}, calls[0])
	assert.True(t, mock.Done())
}

// TestGated_ProductionCompositionKeepsDirRunner is the P37-01 regression: the
// PRODUCTION composition root (internal/cli newRunner = gate.New over
// *shell.ExecRunner) must satisfy the optional shell.DirRunner capability.
// Before the RunInteractiveDir passthrough existed, the decorator silently
// stripped the capability off ExecRunner and the Secure Enclave enrollment
// (`ssh-keygen -K`, HWK-01) was structurally unreachable in the shipped
// binary — while MockRunner-based tests stayed green because MockRunner
// implements RunInteractiveDir directly. Constructing ExecRunner executes
// nothing; no live call is made.
func TestGated_ProductionCompositionKeepsDirRunner(t *testing.T) {
	var r shell.Runner = New(&shell.ExecRunner{}, WithLogger(discardLogger()))
	_, ok := r.(shell.DirRunner)
	require.True(t, ok, "gate.New(&shell.ExecRunner{}) must keep the shell.DirRunner capability — the enclave enroll path type-asserts it")
}

// TestGated_RunInteractiveDirDelegates: shadow mode delegates the working
// directory and argv verbatim to the inner DirRunner and records the exec.
func TestGated_RunInteractiveDirDelegates(t *testing.T) {
	mock := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
	g := New(mock, WithLogger(discardLogger()))

	require.NoError(t, g.RunInteractiveDir(context.Background(), "/work/dir", "ssh-keygen", "-K"))

	recorded := mock.RecordedCalls()
	require.Len(t, recorded, 1)
	assert.Equal(t, "ssh-keygen", recorded[0].Name)
	assert.Equal(t, []string{"-K"}, recorded[0].Args)
	assert.Equal(t, "/work/dir", recorded[0].Dir, "the requested working directory must reach the inner runner untouched")
	assert.True(t, recorded[0].IsInteractive)
	assert.Equal(t, uint64(1), g.Count(), "RunInteractiveDir must be recorded like every other exec")
}

// TestGated_RunInteractiveDirInnerWithoutCapability: an inner runner without
// shell.DirRunner is refused with an error (fail closed) — the gate never
// works around the missing capability by chdir'ing or running in an
// uncontrolled CWD.
func TestGated_RunInteractiveDirInnerWithoutCapability(t *testing.T) {
	inner := &fakeInner{} // fakeInner deliberately has no RunInteractiveDir
	g := New(inner, WithLogger(discardLogger()))

	err := g.RunInteractiveDir(context.Background(), t.TempDir(), "ssh-keygen", "-K")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DirRunner")
	assert.Empty(t, inner.seen(), "no inner method may run when the capability is missing")
}

// TestGated_RunInteractiveDirEnforcingNoToken: enforcing mode applies the same
// approval gate to RunInteractiveDir as to every other Run method — the new
// passthrough must not become an enforcement bypass.
func TestGated_RunInteractiveDirEnforcingNoToken(t *testing.T) {
	mock := shell.NewMockRunner()
	g := New(mock, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)))

	err := g.RunInteractiveDir(context.Background(), "/work/dir", "ssh-keygen", "-K")
	require.ErrorIs(t, err, ErrApprovalRequired)
	assert.Empty(t, mock.RecordedCalls(), "inner must NOT be called when the approval token is missing")
	assert.Equal(t, uint64(1), g.Count(), "counter still incremented on enforcing refusal")
}

// TestGated_CounterPerMethod: one call per Runner method increments the
// atomic counter to exactly 5 — the /status seam proof.
func TestGated_CounterPerMethod(t *testing.T) {
	inner := &fakeInner{stream: &shell.Stream{}}
	g := New(inner, WithLogger(discardLogger()))
	ctx := context.Background()

	_, _ = g.Run(ctx, "true")
	_, _ = g.RunWithStdin(ctx, strings.NewReader(""), "cat")
	_ = g.RunInteractive(ctx, "true")
	_, _ = g.RunWithEnv(ctx, nil, "true")
	_, _ = g.RunStream(ctx, "tmux", "-CC")

	assert.Equal(t, uint64(5), g.Count())
}

// TestGated_CounterConcurrent: 8 goroutines hammering the gate under -race
// count exactly, with no lost increments.
func TestGated_CounterConcurrent(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 25

	inner := &fakeInner{}
	g := New(inner, WithLogger(discardLogger()))
	ctx := context.Background()

	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range perGoroutine {
				_, _ = g.Run(ctx, "true")
			}
		})
	}
	wg.Wait()

	assert.Equal(t, uint64(goroutines*perGoroutine), g.Count())
}

// TestGated_LogHygiene is the D-38 / T-27-14 regression: the debug record
// carries the binary name and hash keys but NEVER a raw argument — args can
// hold user paths, hostnames, and tokens-by-accident.
func TestGated_LogHygiene(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	inner := &fakeInner{}
	g := New(inner, WithLogger(logger))

	_, _ = g.Run(context.Background(), "rsync", "/Users/secret-host-path")

	out := buf.String()
	assert.Contains(t, out, "argv_sha256", "record must carry the argv hash key")
	assert.Contains(t, out, "closure_sha256", "record must carry the closure hash key")
	assert.Contains(t, out, "rsync", "binary name is the one allowed cleartext field")
	assert.NotContains(t, out, "secret-host-path", "raw argv must NEVER reach the log (D-38)")
}

// TestClosureHash_Stability covers the D-39 contract: deterministic for
// identical (name, args, cwd); any argv change changes it; and when args[0]
// names a readable regular file, the file CONTENT is folded in — editing the
// script changes the hash even though the path is unchanged.
func TestClosureHash_Stability(t *testing.T) {
	t.Run("deterministic for identical inputs", func(t *testing.T) {
		h1 := closureHash("ls", []string{"-l", "/tmp"})
		h2 := closureHash("ls", []string{"-l", "/tmp"})
		assert.Equal(t, h1, h2)
	})

	t.Run("argv change changes the hash", func(t *testing.T) {
		h1 := closureHash("ls", []string{"-l", "/tmp"})
		h2 := closureHash("ls", []string{"-a", "/tmp"})
		assert.NotEqual(t, h1, h2)
	})

	t.Run("script content change changes the hash", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "deploy.sh")
		require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho one\n"), 0o700))
		before := closureHash("sh", []string{script})

		require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho two\n"), 0o700))
		after := closureHash("sh", []string{script})

		assert.NotEqual(t, before, after, "same path, different content must differ (D-39)")
	})

	t.Run("missing script file degrades silently", func(t *testing.T) {
		h := closureHash("sh", []string{"/nonexistent/path/to/script.sh"})
		assert.NotEqual(t, [32]byte{}, h, "record must degrade to fallback values, never fail")
	})
}

// TestGated_ShadowMode: gate constructed with no WithEnforcing — must never
// block, must call inner, must increment counter (D-04 shadow default).
func TestGated_ShadowMode(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "ok"}}
	g := New(inner, WithLogger(discardLogger()))
	ctx := context.Background()

	res, err := g.Run(ctx, "echo", "hello")
	require.NoError(t, err)
	assert.Equal(t, "ok", res.Stdout)
	assert.Contains(t, inner.seen(), "Run", "inner must be called in shadow mode")
	assert.Equal(t, uint64(1), g.Count(), "counter incremented in shadow mode")
}

// TestGated_EnforcingNoToken: enforcing gate + no ApprovalToken in ctx →
// ErrApprovalRequired; inner.Run must NOT be called; counter still incremented.
func TestGated_EnforcingNoToken(t *testing.T) {
	inner := &fakeInner{}
	fakeReg := approve.NewRegistry(nil)
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(fakeReg))
	ctx := context.Background() // no token attached

	_, err := g.Run(ctx, "echo", "hello")
	require.ErrorIs(t, err, ErrApprovalRequired)
	assert.NotContains(t, inner.seen(), "Run", "inner must NOT be called when token is missing")
	assert.Equal(t, uint64(1), g.Count(), "counter still incremented even on enforcing refusal")
}

// TestGated_ClosureHashMismatch: enforcing gate + wrong ClosureHash in token →
// ErrClosureHashMismatch; inner.Run must NOT be called.
func TestGated_ClosureHashMismatch(t *testing.T) {
	inner := &fakeInner{}
	fakeReg := approve.NewRegistry(nil)
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(fakeReg))

	wrongHash := [32]byte{} // all zeros — never matches real closureHash
	tok := &approveToken{ClosureHash: wrongHash}
	ctx := WithApprovalToken(context.Background(), tok)

	_, err := g.Run(ctx, "echo", "hello")
	require.ErrorIs(t, err, ErrClosureHashMismatch)
	assert.NotContains(t, inner.seen(), "Run", "inner must NOT be called on hash mismatch")
}

// TestGated_ClosureHashMatch: enforcing gate + correct ClosureHash →
// inner.Run IS called.
func TestGated_ClosureHashMatch(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "matched"}}
	fakeReg := approve.NewRegistry(nil)
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(fakeReg))

	correctHash := closureHash("echo", []string{"hello"})
	tok := &approveToken{ClosureHash: correctHash}
	ctx := WithApprovalToken(context.Background(), tok)

	res, err := g.Run(ctx, "echo", "hello")
	require.NoError(t, err)
	assert.Equal(t, "matched", res.Stdout)
	assert.Contains(t, inner.seen(), "Run", "inner must be called on hash match")
}

// TestGated_InternalBypass: gate constructed with plain New (no WithEnforcing) —
// must delegate without any approval check, even if other instances have a
// registry. This proves the D-40 structural bypass: enforcing is purely at
// construction time, never toggleable after construction.
func TestGated_InternalBypass(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "bypass"}}
	// plain New — no WithEnforcing
	g := New(inner, WithLogger(discardLogger()))
	ctx := context.Background() // no token

	res, err := g.Run(ctx, "tmux", "-CC", "attach-session")
	require.NoError(t, err)
	assert.Equal(t, "bypass", res.Stdout, "daemon-internal runner must never block")
	assert.Contains(t, inner.seen(), "Run")
}

// TestGated_TokenInContext: WithApprovalToken/approvalTokenFromCtx round-trip.
func TestGated_TokenInContext(t *testing.T) {
	tok := &approveToken{ClosureHash: [32]byte{1, 2, 3}}
	ctx := WithApprovalToken(context.Background(), tok)
	got, ok := approvalTokenFromCtx(ctx)
	require.True(t, ok, "token must be found after WithApprovalToken")
	assert.Equal(t, tok, got)

	_, ok2 := approvalTokenFromCtx(context.Background())
	assert.False(t, ok2, "empty ctx must return false")
}

// TestGated_CounterShadow: shadow mode increments Count() on every Run (Phase
// 27 behavior preserved across all five methods).
func TestGated_CounterShadow(t *testing.T) {
	inner := &fakeInner{stream: &shell.Stream{}}
	g := New(inner, WithLogger(discardLogger()))
	ctx := context.Background()

	_, _ = g.Run(ctx, "true")
	_, _ = g.RunWithStdin(ctx, strings.NewReader(""), "cat")
	_ = g.RunInteractive(ctx, "true")
	_, _ = g.RunWithEnv(ctx, nil, "true")
	_, _ = g.RunStream(ctx, "tmux", "-CC")
	assert.Equal(t, uint64(5), g.Count(), "all five methods must increment in shadow mode")
}

// TestGate_NoOSExecImport enforces the CLAUDE.md monopoly at the source level:
// internal/gate must resolve binaries via shell.ResolvePath, never os/exec.
func TestGate_NoOSExecImport(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, perr)
		for _, imp := range f.Imports {
			assert.NotEqual(t, `"os/exec"`, imp.Path.Value,
				"%s must not import os/exec (use shell.ResolvePath)", name)
		}
		checked++
	}
	assert.Positive(t, checked, "expected at least one non-test source file to check")
}

// TestGate_NoClaude enforces the APPR-06 quarantine: internal/gate must never
// import claudecode. The gate package may import internal/approve (its downstream
// dependency) but must never import the claudecode consumer module — doing so
// would create a forbidden circular dependency in the architecture.
//
// Forbidden import strings:
//   - "claudecode"  — gate must never pull in Claude-specific code
func TestGate_NoClaude(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly|parser.ParseComments)
		require.NoError(t, perr, "failed to parse %s", name)
		for _, imp := range f.Imports {
			path := imp.Path.Value
			assert.NotContains(t, path, "claudecode",
				"%s must not import claudecode (APPR-06: gate is a generic mechanism, not Claude-specific)", name)
		}
		checked++
	}
	assert.Positive(t, checked, "expected at least one non-test source file to check")
}
