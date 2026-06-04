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
	"io"
	"sync"
)

// Call represents a scripted invocation in a MockRunner.
type Call struct {
	Name          string
	Args          []string
	Stdin         string            // captured stdin content from RunWithStdin (empty for Run calls)
	Env           map[string]string // extra env vars passed via RunWithEnv
	IsInteractive bool              // true when the call was made via RunInteractive
	Result        Result
	Err           error
}

// MockRunner replays pre-scripted Calls in order. Tests use this to avoid
// executing real processes. After replay, RecordedCalls returns each call
// enriched with the actual Name and Args that were passed to Run.
type MockRunner struct {
	mu    sync.Mutex
	calls []Call
	idx   int
}

// NewMockRunner returns a MockRunner that will replay calls in order.
func NewMockRunner(calls ...Call) *MockRunner {
	return &MockRunner{calls: calls}
}

// Run returns the next scripted Call result. It returns an error if more calls
// are made than were scripted. The actual name and args are stored in the call
// record so they can be inspected via RecordedCalls.
func (m *MockRunner) Run(_ context.Context, name string, args ...string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.calls) {
		return Result{}, fmt.Errorf("shell: unexpected call %d: %s %v", m.idx, name, args)
	}
	c := m.calls[m.idx]
	// Record the actual name and args for later inspection.
	m.calls[m.idx].Name = name
	m.calls[m.idx].Args = args
	m.idx++
	return c.Result, c.Err
}

// RunWithStdin returns the next scripted Call result, reading the stdin content
// for later assertion via RecordedCalls. It behaves identically to Run for
// scripted result replay but also stores the actual name, args, and stdin bytes
// in the recorded call.
func (m *MockRunner) RunWithStdin(_ context.Context, stdin io.Reader, name string, args ...string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.calls) {
		return Result{}, fmt.Errorf("shell: unexpected call %d (RunWithStdin): %s %v", m.idx, name, args)
	}
	c := m.calls[m.idx]
	// Record the actual name and args for later inspection.
	m.calls[m.idx].Name = name
	m.calls[m.idx].Args = args
	m.idx++

	if stdin != nil {
		data, _ := io.ReadAll(stdin)
		c.Stdin = string(data)
		// store the captured stdin back in the calls slice so callers can inspect it
		m.calls[m.idx-1].Stdin = c.Stdin
	}

	return c.Result, c.Err
}

// RunInteractive returns an error for the next scripted Call, recording the
// actual name and args. The recorded call is stamped with IsInteractive=true so
// tests can distinguish RunInteractive calls from Run calls via
// RunInteractiveCalls().
//
// Interactive calls do not capture output, so c.Result.Stdout/Stderr are ignored.
// A scripted non-zero c.Result.ExitCode is, however, mapped to an error to mirror
// the real ExecRunner.RunInteractive, which returns exec.Cmd.Run's *exec.ExitError
// for a non-zero exit. An explicit c.Err always takes precedence so tests can
// script an arbitrary failure. Scripting Result.ExitCode: 0 yields nil (success),
// keeping existing success-path tests green.
func (m *MockRunner) RunInteractive(_ context.Context, name string, args ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.calls) {
		return fmt.Errorf("shell: unexpected call %d (RunInteractive): %s %v", m.idx, name, args)
	}
	c := m.calls[m.idx]
	m.calls[m.idx].Name = name
	m.calls[m.idx].Args = args
	m.calls[m.idx].IsInteractive = true
	m.idx++
	if c.Err != nil {
		return c.Err
	}
	if c.Result.ExitCode != 0 {
		return fmt.Errorf("shell: interactive command %q exited with code %d", name, c.Result.ExitCode)
	}
	return nil
}

// RunInteractiveCalls returns the full argv (name prepended to args) for every
// call that was made via RunInteractive. Returns a non-nil empty slice when no
// interactive calls have been recorded. Safe to call concurrently.
func (m *MockRunner) RunInteractiveCalls() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]string, 0)
	for _, c := range m.calls[:m.idx] {
		if c.IsInteractive {
			argv := make([]string, 0, 1+len(c.Args))
			argv = append(argv, c.Name)
			argv = append(argv, c.Args...)
			out = append(out, argv)
		}
	}
	return out
}

// RunCalls returns the full argv (name prepended to args) for every call that
// was made via Run (not RunInteractive, RunWithStdin, or RunWithEnv). Returns a
// non-nil empty slice when no such calls have been recorded. Safe to call concurrently.
func (m *MockRunner) RunCalls() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]string, 0)
	for _, c := range m.calls[:m.idx] {
		if !c.IsInteractive {
			argv := make([]string, 0, 1+len(c.Args))
			argv = append(argv, c.Name)
			argv = append(argv, c.Args...)
			out = append(out, argv)
		}
	}
	return out
}

// RunWithEnv returns the next scripted Call result. The env map is recorded for
// later inspection via RecordedCalls but does not affect the scripted output.
func (m *MockRunner) RunWithEnv(_ context.Context, env map[string]string, name string, args ...string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.calls) {
		return Result{}, fmt.Errorf("shell: unexpected call %d (RunWithEnv): %s %v", m.idx, name, args)
	}
	c := m.calls[m.idx]
	m.calls[m.idx].Name = name
	m.calls[m.idx].Args = args
	m.calls[m.idx].Env = env
	m.idx++
	return c.Result, c.Err
}

// RecordedCalls returns a snapshot of all calls as consumed so far, including
// any stdin content captured by RunWithStdin.
func (m *MockRunner) RecordedCalls() []Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Call, m.idx)
	copy(out, m.calls[:m.idx])
	return out
}

// Done reports whether all scripted calls were consumed.
func (m *MockRunner) Done() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.idx == len(m.calls)
}
