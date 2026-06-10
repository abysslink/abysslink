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
	"bufio"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"sync"
)

const (
	// maxStreamLineBytes bounds a single protocol line from a streamed process
	// (D-36 / T-27-05). tmux control-mode notifications are short, but pane
	// output echoed through the protocol is attacker-influenced; 1 MiB matches
	// the file watcher's maxScanLine headroom while still bounding memory per
	// stream. An over-cap line is truncated, flagged, and the stream CONTINUES
	// — never an ErrTooLong-style stop (Pitfall 1).
	maxStreamLineBytes = 1 * 1024 * 1024 // 1 MiB

	// streamChanDepth bounds the Lines channel so a slow consumer applies
	// backpressure to the subprocess via the OS pipe instead of growing
	// daemon memory without limit (T-27-05).
	streamChanDepth = 256
)

// streamLogger is the logger used by RunStream's stderr drain (D-37). nil
// means slog.Default(), resolved at stream start so tests can inject a
// capturing handler.
//
//nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam for the stderr drain logger; intentional
var streamLogger *slog.Logger

// Line is one stdout line from a streaming process. Truncated is true when
// the per-line cap was hit and the remainder of the line discarded (D-36).
type Line struct {
	Text      string
	Truncated bool
}

// Stream is a handle to a long-lived line-oriented process (D-33). It is one
// process lifetime: when the process exits (or is killed), Lines closes and
// Wait returns. Reconnect/backoff is deliberately the caller's job (D-34).
type Stream struct {
	lines chan Line
	stdin io.WriteCloser
	// kill terminates the process (or stops mock playback); idempotent.
	kill func()
	// waitFn blocks until the reader goroutines finish and the process is
	// reaped; called exactly once under waitOnce.
	waitFn    func() error
	waitOnce  sync.Once
	waitErr   error
	closeOnce sync.Once
	closeErr  error
}

// Lines returns the channel of stdout protocol lines. It closes when the
// process's stdout reaches EOF (process exit, kill, or ctx cancel).
func (s *Stream) Lines() <-chan Line { return s.lines }

// Stdin returns the process's stdin. Control-mode commands ride the same
// connection as the notification stream (D-33).
func (s *Stream) Stdin() io.Writer { return s.stdin }

// Wait blocks until the reader goroutines have drained the pipes and the
// process has been reaped (os/exec ordering constraint — Pitfall 2: the
// process must never be reaped before pipe reads complete). It returns nil on
// exit code 0, otherwise an error carrying the exit status. This deviates
// from Run's Result-value convention deliberately: a stream has no captured
// output, so there is no Result to return — only the exit disposition.
func (s *Stream) Wait() error {
	s.waitOnce.Do(func() { s.waitErr = s.waitFn() })
	return s.waitErr
}

// Close kills the process (which EOFs the pipes and unblocks the reader
// goroutines and Wait), reaps it, and returns the exit error. It is
// idempotent: subsequent calls return the first call's result.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.kill()
		s.closeErr = s.Wait()
	})
	return s.closeErr
}

// RunStream starts name with args and returns a Stream handle over its
// stdout. The reader goroutine owns the stdout pipe until EOF, delivering
// bounded lines (D-36) on the Lines channel; stderr is drained line-by-line
// to slog at Warn and never enters the protocol channel (D-37). Cancelling
// ctx (or calling Close) kills the process, which EOFs the pipes and
// unblocks everything (T-27-06).
func (r *ExecRunner) RunStream(ctx context.Context, name string, args ...string) (*Stream, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(streamCtx, name, args...) //nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	logger := streamLogger
	if logger == nil {
		logger = slog.Default()
	}

	lines := make(chan Line, streamChanDepth)
	var pipes sync.WaitGroup
	pipes.Add(2)

	// Stdout reader: owns the pipe until EOF (Pitfall 2). A send blocked on a
	// full channel aborts on streamCtx.Done so Close can always unblock it.
	go func() {
		defer pipes.Done()
		defer close(lines)
		readBoundedLines(stdout, func(ln Line) bool {
			select {
			case lines <- ln:
				return true
			case <-streamCtx.Done():
				return false
			}
		})
	}()

	// Stderr drain (D-37 / T-27-07): line-by-line to slog with the same
	// per-line cap; stderr never enters the protocol channel.
	go func() {
		defer pipes.Done()
		readBoundedLines(stderr, func(ln Line) bool {
			logger.Warn("shell: stream stderr", "binary", name, "line", ln.Text, "truncated", ln.Truncated)
			return true
		})
	}()

	return &Stream{
		lines: lines,
		stdin: stdin,
		kill:  cancel,
		waitFn: func() error {
			pipes.Wait()
			waitErr := cmd.Wait()
			cancel() // release the derived context once reaped
			return waitErr
		},
	}, nil
}

// readBoundedLines consumes r line-by-line with the D-36 per-line cap,
// calling emit for each line. When a line exceeds maxStreamLineBytes the
// first maxStreamLineBytes bytes are emitted with Truncated=true and the
// remainder is discarded up to the next '\n' — the loop then continues
// (Pitfall 1: never stop the stream on a long line). On EOF any final
// partial line is emitted. emit returning false aborts the read.
func readBoundedLines(r io.Reader, emit func(Line) bool) {
	br := bufio.NewReaderSize(r, 64*1024)
	buf := make([]byte, 0, 4096)
	discarding := false
	for {
		chunk, err := br.ReadSlice('\n')
		hasNL := len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
		data := chunk
		if hasNL {
			data = chunk[:len(chunk)-1]
		}
		switch {
		case discarding:
			// Over-cap head already emitted; drop bytes until the newline.
		case len(buf)+len(data) > maxStreamLineBytes:
			keep := maxStreamLineBytes - len(buf)
			buf = append(buf, data[:keep]...)
			if !emit(Line{Text: string(buf), Truncated: true}) {
				return
			}
			buf = buf[:0]
			discarding = true
		default:
			buf = append(buf, data...)
		}
		if hasNL {
			if !discarding {
				if !emit(Line{Text: string(buf)}) {
					return
				}
				buf = buf[:0]
			}
			discarding = false
		}
		if err != nil {
			if err == bufio.ErrBufferFull {
				continue
			}
			// EOF or read error: deliver any final partial line, then stop.
			if !discarding && len(buf) > 0 {
				emit(Line{Text: string(buf)})
			}
			return
		}
	}
}
