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
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// swapDefaultLogger installs a slog default writing to the returned buffer and
// registers cleanup restoring the original default after the test.
func swapDefaultLogger(t *testing.T, level slog.Level) (*bytes.Buffer, *slog.Logger) {
	t.Helper()
	var prevBuf bytes.Buffer
	prevLogger := slog.New(slog.NewTextHandler(&prevBuf, &slog.HandlerOptions{Level: level}))
	old := slog.Default()
	slog.SetDefault(prevLogger)
	t.Cleanup(func() { slog.SetDefault(old) })
	return &prevBuf, prevLogger
}

// TestCaptureSlog_BuffersAndFlushesOnRestore is the F-64 regression guard:
// slog lines emitted while the capture is active must NOT reach the previous
// handler (the live terminal), and must be flushed verbatim to the target
// writer when restore() runs — table-then-logs ordering, no log lost.
func TestCaptureSlog_BuffersAndFlushesOnRestore(t *testing.T) {
	prevBuf, prevLogger := swapDefaultLogger(t, slog.LevelInfo)

	var target bytes.Buffer
	restore := captureSlog(&target)

	slog.Warn("launchctl start ntfy skipped", "reason", "test")
	assert.Empty(t, target.String(), "logs must be buffered, not written to target, during the capture window")
	assert.Empty(t, prevBuf.String(), "no log may reach the previous handler (the terminal) during capture (F-64)")

	restore()
	assert.Contains(t, target.String(), "launchctl start ntfy skipped", "buffered logs must be flushed to target on restore")
	assert.Same(t, prevLogger, slog.Default(), "restore must reinstall the previous default logger")

	// After restore, logging goes to the previous handler again, not target.
	slog.Info("after restore")
	assert.Contains(t, prevBuf.String(), "after restore")
	assert.NotContains(t, target.String(), "after restore")
}

// TestCaptureSlog_RestoreIdempotent asserts a second restore() call neither
// double-flushes nor disturbs the reinstalled default.
func TestCaptureSlog_RestoreIdempotent(t *testing.T) {
	_, prevLogger := swapDefaultLogger(t, slog.LevelInfo)

	var target bytes.Buffer
	restore := captureSlog(&target)
	slog.Warn("once")
	restore()
	first := target.String()
	restore()
	assert.Equal(t, first, target.String(), "second restore must not flush again")
	assert.Same(t, prevLogger, slog.Default())
}

// TestCaptureSlog_InheritsLevel asserts the capture handler mirrors the
// previous default's effective minimum level instead of resetting it.
func TestCaptureSlog_InheritsLevel(t *testing.T) {
	swapDefaultLogger(t, slog.LevelWarn)

	var target bytes.Buffer
	restore := captureSlog(&target)
	slog.Info("dropped at warn level")
	slog.Warn("kept at warn level")
	restore()

	assert.NotContains(t, target.String(), "dropped at warn level")
	assert.Contains(t, target.String(), "kept at warn level")
}

// TestCaptureSlog_ConcurrentWriters asserts the capture buffer is safe for
// concurrent slog writers (the ApplyAll worker goroutine logs through
// slog.Default while the UI goroutine runs) and that every line survives.
func TestCaptureSlog_ConcurrentWriters(t *testing.T) {
	swapDefaultLogger(t, slog.LevelInfo)

	var target bytes.Buffer
	restore := captureSlog(&target)

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			slog.Warn(fmt.Sprintf("concurrent line %d", id))
		}(i)
	}
	wg.Wait()
	restore()

	for i := 0; i < n; i++ {
		require.Contains(t, target.String(), fmt.Sprintf("concurrent line %d", i))
	}
}
