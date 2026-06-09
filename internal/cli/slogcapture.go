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

package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
)

// captureSlog swaps slog.Default() for a logger that writes to an in-memory
// buffer, and returns a restore func that puts the previous default back and
// flushes the buffered bytes to target (F-64).
//
// Rationale: while a Bubble Tea live table owns the terminal, any slog line
// written straight to stderr (e.g. "WARN notify apply: launchctl start ntfy
// skipped...") corrupts the rendered rows. Capturing during the animation
// window and flushing after the tea program exits preserves every log line
// while guaranteeing table-then-logs ordering.
//
// The capture logger preserves the effective minimum level of the previous
// default handler, so verbosity settings carry through the capture window.
//
// Concurrency: the buffer is mutex-guarded — ApplyAll/PlanAll worker
// goroutines log through slog.Default concurrently with the UI goroutine.
// Callers must swap BEFORE starting the worker and call restore only after
// the table is closed AND the worker has finished. restore is idempotent.
func captureSlog(target io.Writer) (restore func()) {
	prev := slog.Default()
	buf := &lockedBuffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: minEnabledLevel(prev.Handler()),
	})
	slog.SetDefault(slog.New(handler))

	var once sync.Once
	return func() {
		once.Do(func() {
			slog.SetDefault(prev)
			if b := buf.snapshot(); len(b) > 0 {
				_, _ = target.Write(b)
			}
		})
	}
}

// minEnabledLevel probes a handler for the lowest level it accepts, so the
// capture handler mirrors the previous default's effective verbosity.
func minEnabledLevel(h slog.Handler) slog.Level {
	ctx := context.Background()
	for _, l := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn} {
		if h.Enabled(ctx, l) {
			return l
		}
	}
	return slog.LevelError
}

// lockedBuffer is a goroutine-safe append-only byte buffer. slog handlers
// serialize their own writes per-record, but multiple goroutines logging
// through the same handler still race on the underlying writer.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write implements io.Writer.
func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// snapshot returns a copy of the buffered bytes.
func (b *lockedBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}
