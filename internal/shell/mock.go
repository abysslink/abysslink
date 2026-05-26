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
	Name   string
	Args   []string
	Stdin  string // captured stdin content from RunWithStdin (empty for Run calls)
	Result Result
	Err    error
}

// MockRunner replays pre-scripted Calls in order. Tests use this to avoid
// executing real processes.
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
// are made than were scripted.
func (m *MockRunner) Run(_ context.Context, name string, args ...string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.calls) {
		return Result{}, fmt.Errorf("shell: unexpected call %d: %s %v", m.idx, name, args)
	}
	c := m.calls[m.idx]
	m.idx++
	return c.Result, c.Err
}

// RunWithStdin returns the next scripted Call result, reading the stdin content
// for later assertion via RecordedCalls. It behaves identically to Run for
// scripted result replay but also stores the stdin bytes in the recorded call.
func (m *MockRunner) RunWithStdin(_ context.Context, stdin io.Reader, name string, args ...string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.calls) {
		return Result{}, fmt.Errorf("shell: unexpected call %d (RunWithStdin): %s %v", m.idx, name, args)
	}
	c := m.calls[m.idx]
	m.idx++

	if stdin != nil {
		data, _ := io.ReadAll(stdin)
		c.Stdin = string(data)
		// store the captured stdin back in the calls slice so callers can inspect it
		m.calls[m.idx-1].Stdin = c.Stdin
	}

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
