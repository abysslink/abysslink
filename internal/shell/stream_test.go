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

package shell

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recvLine receives one Line from ch or fails the test after timeout.
// The second return reports whether the channel was still open.
func recvLine(t *testing.T, ch <-chan Line, timeout time.Duration) (Line, bool) {
	t.Helper()
	select {
	case ln, ok := <-ch:
		return ln, ok
	case <-time.After(timeout):
		t.Fatalf("timed out after %v waiting for a line", timeout)
		return Line{}, false
	}
}

// requireClosed asserts ch closes (delivering no further lines) within timeout.
func requireClosed(t *testing.T, ch <-chan Line, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ln, ok := <-ch:
			if !ok {
				return
			}
			t.Fatalf("expected channel close, got line %q", ln.Text)
		case <-deadline:
			t.Fatalf("timed out after %v waiting for Lines() to close", timeout)
		}
	}
}

// TestRunStreamEcho verifies the happy path: a short-lived process's stdout
// arrives on Lines(), the channel closes on EOF, and Wait returns nil for
// exit code 0.
func TestRunStreamEcho(t *testing.T) {
	r := &ExecRunner{}
	s, err := r.RunStream(context.Background(), "/bin/echo", "hello", "world")
	require.NoError(t, err)

	ln, ok := recvLine(t, s.Lines(), 5*time.Second)
	require.True(t, ok, "expected a line before channel close")
	assert.Equal(t, "hello world", ln.Text)
	assert.False(t, ln.Truncated)

	requireClosed(t, s.Lines(), 5*time.Second)
	assert.NoError(t, s.Wait())
}

// TestRunStreamTruncation verifies D-36: a line longer than maxStreamLineBytes
// is delivered truncated and flagged, and the stream SURVIVES — a subsequent
// normal line still arrives intact (Pitfall 1: never an ErrTooLong stop).
func TestRunStreamTruncation(t *testing.T) {
	r := &ExecRunner{}
	s, err := r.RunStream(context.Background(), "cat")
	require.NoError(t, err)

	go func() {
		w := s.Stdin()
		big := strings.Repeat("a", maxStreamLineBytes+512)
		_, _ = io.WriteString(w, big+"\n")
		_, _ = io.WriteString(w, "tail\n")
		_ = s.stdin.Close() // EOF cat so the stream ends naturally
	}()

	ln1, ok := recvLine(t, s.Lines(), 10*time.Second)
	require.True(t, ok)
	assert.True(t, ln1.Truncated, "over-cap line must be flagged Truncated")
	assert.Len(t, ln1.Text, maxStreamLineBytes, "truncated head must be exactly maxStreamLineBytes")

	ln2, ok := recvLine(t, s.Lines(), 10*time.Second)
	require.True(t, ok, "stream must survive a truncated line")
	assert.Equal(t, "tail", ln2.Text)
	assert.False(t, ln2.Truncated)

	requireClosed(t, s.Lines(), 5*time.Second)
	assert.NoError(t, s.Wait())
}

// TestRunStreamStdin verifies D-33: writes to Stdin() reach the process and
// its responses ride the same connection back on Lines().
func TestRunStreamStdin(t *testing.T) {
	r := &ExecRunner{}
	s, err := r.RunStream(context.Background(), "cat")
	require.NoError(t, err)

	_, err = io.WriteString(s.Stdin(), "ping\n")
	require.NoError(t, err)

	ln, ok := recvLine(t, s.Lines(), 5*time.Second)
	require.True(t, ok)
	assert.Equal(t, "ping", ln.Text)

	require.NoError(t, s.stdin.Close())
	requireClosed(t, s.Lines(), 5*time.Second)
	assert.NoError(t, s.Wait())
}

// TestRunStreamCtxCancel verifies the lifecycle half of the seam: cancelling
// ctx kills the streamed process, closes the line channel, unblocks Wait with
// a non-nil error, and leaks no goroutines (T-27-06).
func TestRunStreamCtxCancel(t *testing.T) {
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	r := &ExecRunner{}
	s, err := r.RunStream(ctx, "cat") // cat with no input blocks forever
	require.NoError(t, err)

	cancel()

	requireClosed(t, s.Lines(), 5*time.Second)

	waitErr := make(chan error, 1)
	go func() { waitErr <- s.Wait() }()
	select {
	case err := <-waitErr:
		assert.Error(t, err, "Wait must surface the kill as an error")
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() did not unblock within 5s after ctx cancel")
	}

	// Goroutine count must return to baseline (retry loop: reaping is async).
	for i := 0; i < 100; i++ {
		if runtime.NumGoroutine() <= before {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "goroutine leak after ctx cancel")
}

// TestStreamCloseIdempotent verifies Close kills + reaps exactly once and a
// second call returns the same error without panicking.
func TestStreamCloseIdempotent(t *testing.T) {
	r := &ExecRunner{}
	s, err := r.RunStream(context.Background(), "cat")
	require.NoError(t, err)

	c1 := s.Close()
	c2 := s.Close()
	assert.Equal(t, c1, c2, "second Close must return the same result as the first")

	requireClosed(t, s.Lines(), 5*time.Second)
}

// TestRunStreamStderr verifies D-37 / T-27-07: stderr output never enters the
// protocol channel — it is drained line-by-line to slog at Warn.
func TestRunStreamStderr(t *testing.T) {
	var buf bytes.Buffer
	old := streamLogger
	streamLogger = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { streamLogger = old })

	r := &ExecRunner{}
	s, err := r.RunStream(context.Background(), "cat", "/nonexistent-path-xyz")
	require.NoError(t, err)

	// cat prints its error to stderr and exits non-zero; the protocol channel
	// must stay empty of it.
	for ln := range s.Lines() {
		t.Errorf("stderr leaked onto the protocol channel: %q", ln.Text)
	}
	assert.Error(t, s.Wait(), "cat on a missing path must exit non-zero")

	// Wait() returning guarantees the stderr drain goroutine finished.
	assert.Contains(t, buf.String(), "nonexistent-path-xyz",
		"stderr text must land in slog")
}

// TestResolvePath verifies the package helper that lets internal/gate resolve
// binary paths without importing os/exec (CLAUDE.md monopoly rule).
func TestResolvePath(t *testing.T) {
	p, err := ResolvePath("cat")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(p), "ResolvePath must return an absolute path, got %q", p)

	_, err = ResolvePath("definitely-not-a-binary-xyz")
	assert.Error(t, err)
}
