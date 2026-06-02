//go:build webui

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

package webui

import (
	"sync"
	"time"
)

// ringCapacity is the fixed number of notify events the dashboard retains in
// memory (WEB-07). The buffer is intentionally bounded and non-persistent — it
// is a convenience view, not an audit trail.
const ringCapacity = 100

// NotifyEvent is a single notification observed by the daemon, projected for
// the read-only notify-history view. It carries no secret body content.
type NotifyEvent struct {
	Time     time.Time
	Title    string
	Topic    string
	Priority string
}

// NotifyRingBuffer is a thread-safe, fixed-capacity ring of the most recent
// NotifyEvents. When full, the oldest event is dropped. The zero value is not
// usable; construct via NewNotifyRingBuffer.
type NotifyRingBuffer struct {
	mu   sync.Mutex
	buf  []NotifyEvent
	next int  // index of the next write slot
	full bool // whether the ring has wrapped at least once
}

// NewNotifyRingBuffer returns an empty ring with the compiled-in capacity.
func NewNotifyRingBuffer() *NotifyRingBuffer {
	return &NotifyRingBuffer{buf: make([]NotifyEvent, ringCapacity)}
}

// Add appends e to the ring, dropping the oldest event when the ring is full.
func (r *NotifyRingBuffer) Add(e NotifyEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % ringCapacity
	if r.next == 0 {
		r.full = true
	}
}

// Snapshot returns a copy of the ring's current contents, newest-first. The
// returned slice is owned by the caller and is safe to read without locking.
func (r *NotifyRingBuffer) Snapshot() []NotifyEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := r.next
	if r.full {
		n = ringCapacity
	}
	out := make([]NotifyEvent, 0, n)
	// Walk backwards from the most recently written slot so the result is
	// newest-first.
	for i := 0; i < n; i++ {
		idx := (r.next - 1 - i + ringCapacity) % ringCapacity
		out = append(out, r.buf[idx])
	}
	return out
}
