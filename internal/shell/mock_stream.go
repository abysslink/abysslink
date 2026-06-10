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
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// playbackStep is one << emit from a transcript, optionally paced by the
// accumulated @delay directives that preceded it.
type playbackStep struct {
	delay time.Duration
	line  string
}

// Transcript is a parsed D-35 annotated script: the << lines a mock stream
// emits (with @delay pacing) and the >> stdin writes the test expects the
// consumer to have made. Load fixtures with LoadTranscript; check consumer
// writes with Verify.
type Transcript struct {
	path           string
	steps          []playbackStep
	expectedWrites []string
}

// LoadTranscript parses a D-35 annotated script file:
//
//	# comment        — skipped (as are blank lines)
//	<< line          — a protocol line the mock emits onto the channel
//	>> write         — a stdin write the test expects the consumer to make
//	@delay <dur>     — paces the NEXT << emit (time.ParseDuration syntax)
//
// Anything else is an error naming the 1-based line number.
func LoadTranscript(path string) (*Transcript, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a test-fixture path chosen by test code, not user input
	if err != nil {
		return nil, fmt.Errorf("shell: load transcript %s: %w", path, err)
	}
	t := &Transcript{path: path}
	var pending time.Duration
	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		case line == "<<" || strings.HasPrefix(line, "<< "):
			t.steps = append(t.steps, playbackStep{
				delay: pending,
				line:  strings.TrimPrefix(strings.TrimPrefix(line, "<<"), " "),
			})
			pending = 0
		case line == ">>" || strings.HasPrefix(line, ">> "):
			t.expectedWrites = append(t.expectedWrites,
				strings.TrimPrefix(strings.TrimPrefix(line, ">>"), " "))
		case strings.HasPrefix(line, "@delay "):
			d, derr := time.ParseDuration(strings.TrimSpace(strings.TrimPrefix(line, "@delay ")))
			if derr != nil {
				return nil, fmt.Errorf("shell: transcript %s: line %d: bad @delay: %w", path, lineNo, derr)
			}
			pending += d
		default:
			return nil, fmt.Errorf("shell: transcript %s: line %d: unknown directive %q", path, lineNo, trimmed)
		}
	}
	return t, nil
}

// Verify compares the consumer's recorded stdin writes (newline-split, e.g.
// from StreamStdinWrites) against the transcript's >> directives in order.
// It returns nil on an exact match, otherwise a descriptive error naming the
// first mismatch's expected and actual content.
func (t *Transcript) Verify(writes []string) error {
	for i := range t.expectedWrites {
		if i >= len(writes) {
			return fmt.Errorf("shell: transcript %s: stdin write %d: expected %q, got nothing (only %d writes recorded)",
				t.path, i, t.expectedWrites[i], len(writes))
		}
		if writes[i] != t.expectedWrites[i] {
			return fmt.Errorf("shell: transcript %s: stdin write %d: expected %q, got %q",
				t.path, i, t.expectedWrites[i], writes[i])
		}
	}
	if len(writes) > len(t.expectedWrites) {
		return fmt.Errorf("shell: transcript %s: %d extra stdin writes beyond the %d expected; first extra: %q",
			t.path, len(writes)-len(t.expectedWrites), len(t.expectedWrites), writes[len(t.expectedWrites)])
	}
	return nil
}

// AddStream appends a transcript to the scripted-stream queue. Each
// RunStream call consumes one transcript in FIFO order.
func (m *MockRunner) AddStream(t *Transcript) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams = append(m.streams, t)
}

// RunStream consumes the next scripted transcript (mutex-guarded index,
// recording the actual name/args, erroring on over-consumption — mirroring
// mock.go's Run idiom) and returns a *Stream whose channel replays the
// transcript's << lines, honoring @delay pacing, then closes — simulating
// %exit / server death. Writes to the Stream's Stdin are recorded for >>
// assertions via StreamStdinWrites and Transcript.Verify.
func (m *MockRunner) RunStream(ctx context.Context, name string, args ...string) (*Stream, error) {
	m.mu.Lock()
	if m.streamIdx >= len(m.streams) {
		m.mu.Unlock()
		return nil, fmt.Errorf("shell: unexpected call %d (RunStream): %s %v", m.streamIdx, name, args)
	}
	t := m.streams[m.streamIdx]
	m.streamIdx++
	argv := make([]string, 0, 1+len(args))
	argv = append(argv, name)
	argv = append(argv, args...)
	m.streamCalls = append(m.streamCalls, argv)
	m.mu.Unlock()

	playCtx, cancel := context.WithCancel(ctx)
	lines := make(chan Line, streamChanDepth)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(lines)
		for _, st := range t.steps {
			if st.delay > 0 {
				timer := time.NewTimer(st.delay)
				select {
				case <-timer.C:
				case <-playCtx.Done():
					timer.Stop()
					return
				}
			}
			select {
			case lines <- Line{Text: st.line}:
			case <-playCtx.Done():
				return
			}
		}
	}()

	// The mock constructs the Stream's unexported fields directly (same
	// package) so ExecRunner and MockRunner hand consumers the identical
	// handle type — no exported setters on Stream.
	return &Stream{
		lines: lines,
		stdin: &mockStreamStdin{m: m},
		kill:  cancel,
		waitFn: func() error {
			<-done
			cancel()
			return nil
		},
	}, nil
}

// StreamCalls returns the full argv (name prepended to args) for every call
// made via RunStream, mirroring the RunCalls/RunInteractiveCalls idiom.
// Returns a non-nil empty slice when no stream calls were made. Safe to call
// concurrently.
func (m *MockRunner) StreamCalls() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]string, 0, len(m.streamCalls))
	for _, argv := range m.streamCalls {
		cp := make([]string, len(argv))
		copy(cp, argv)
		out = append(out, cp)
	}
	return out
}

// StreamStdinWrites returns everything written to mock streams' Stdin so
// far, split on newline (a trailing newline does not produce an empty final
// element). Snapshot-copy under lock per the RecordedCalls idiom.
func (m *MockRunner) StreamStdinWrites() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := string(m.stdinBuf)
	if s == "" {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// mockStreamStdin records every Write into the owning MockRunner's stdin
// buffer for later >> assertions. Close is a no-op so the mock satisfies the
// same io.WriteCloser shape ExecRunner's stdin pipe provides.
type mockStreamStdin struct {
	m *MockRunner
}

func (w *mockStreamStdin) Write(p []byte) (int, error) {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	w.m.stdinBuf = append(w.m.stdinBuf, p...)
	return len(p), nil
}

func (w *mockStreamStdin) Close() error { return nil }
