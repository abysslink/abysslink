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

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

type recordingNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recordingNotifier) Send(_ context.Context, _, body string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, body)
	return nil
}

func (r *recordingNotifier) SendNote(_ context.Context, _ notifyv2.RenderedNote) error { return nil }

func TestScanFileFrom_NotifiesOnMatchAndTracksOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "build.log")
	require.NoError(t, os.WriteFile(path, []byte("starting\nall good\n"), 0o600))

	rn := &recordingNotifier{}
	s := &Server{notifier: rn}
	re := regexp.MustCompile("FAILED")

	// Initial scan: no match yet, offset advances to end.
	off := s.scanFileFrom(context.Background(), path, 0, re, "build")
	assert.Empty(t, rn.msgs)
	assert.Equal(t, int64(len("starting\nall good\n")), off)

	// Append a matching line; only the new line is scanned from the offset.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, _ = f.WriteString("step 3 FAILED\n")
	_ = f.Close()

	off2 := s.scanFileFrom(context.Background(), path, off, re, "build")
	require.Len(t, rn.msgs, 1)
	assert.Contains(t, rn.msgs[0], "FAILED")
	assert.Greater(t, off2, off)

	// Re-scan with no new lines: no duplicate notification.
	s.scanFileFrom(context.Background(), path, off2, re, "build")
	assert.Len(t, rn.msgs, 1)
}

func TestScanFileFrom_MissingFileIsNoop(t *testing.T) {
	rn := &recordingNotifier{}
	s := &Server{notifier: rn}
	off := s.scanFileFrom(context.Background(), "/no/such/file", 0, regexp.MustCompile("x"), "l")
	assert.Equal(t, int64(0), off)
	assert.Empty(t, rn.msgs)
}

// TestScanFileFrom_LongLineWithinBuffer is the NET-11 regression (part 1):
// a line longer than bufio.Scanner's 64 KiB default — which previously
// stalled the watcher silently — must now be scanned and matched thanks to
// the enlarged 1 MiB buffer.
func TestScanFileFrom_LongLineWithinBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "long.log")
	longLine := strings.Repeat("A", 128*1024) + " FAILED\n" // 128 KiB > 64 KiB default
	require.NoError(t, os.WriteFile(path, []byte(longLine), 0o600))

	rn := &recordingNotifier{}
	s := &Server{notifier: rn}
	re := regexp.MustCompile("FAILED")

	off := s.scanFileFrom(context.Background(), path, 0, re, "long")
	require.Len(t, rn.msgs, 1, "a >64KiB line must be scanned with the enlarged buffer (NET-11)")
	assert.Equal(t, int64(len(longLine)), off)
}

// TestScanFileFrom_PoisonLineRecovers is the NET-11 regression (part 2): a
// line exceeding even the enlarged 1 MiB cap triggers scanner.Err
// (bufio.ErrTooLong). The watcher must not stall at the same offset forever —
// it skips to the end of the file and keeps tailing subsequent appends.
func TestScanFileFrom_PoisonLineRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "poison.log")
	poison := strings.Repeat("B", maxScanLine+1024) // > 1 MiB cap → bufio.ErrTooLong
	require.NoError(t, os.WriteFile(path, []byte(poison+"\n"), 0o600))

	rn := &recordingNotifier{}
	s := &Server{notifier: rn}
	re := regexp.MustCompile("FAILED")

	// First scan hits the poison line: no notification, but the offset must
	// ADVANCE (to end of file), not stay pinned at 0.
	off := s.scanFileFrom(context.Background(), path, 0, re, "poison")
	assert.Empty(t, rn.msgs)
	require.Greater(t, off, int64(0), "offset must advance past a poison line, not stall (NET-11)")

	// Subsequent appends after the poison line are still picked up.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, _ = f.WriteString("step 9 FAILED\n")
	_ = f.Close()

	off2 := s.scanFileFrom(context.Background(), path, off, re, "poison")
	require.Len(t, rn.msgs, 1, "watcher must keep working after recovering from a poison line")
	assert.Contains(t, rn.msgs[0], "FAILED")
	assert.Greater(t, off2, off)
}
