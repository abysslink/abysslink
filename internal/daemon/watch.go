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
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/abysslink/abysslink/internal/config"
)

const (
	filePollInterval    = 2 * time.Second
	defaultHTTPInterval = 60 * time.Second
	maxBodyLine         = 200
	// maxScanLine bounds a single watched-file line (NET-11). bufio.Scanner's
	// default 64 KiB cap is easily exceeded by real-world log lines (JSON
	// blobs, stack traces); 1 MiB gives generous headroom while still bounding
	// memory per watcher.
	maxScanLine = 1 << 20 // 1 MiB
)

// startFileAndHTTPWatchers launches the configured file and HTTP watchers.
func (s *Server) startFileAndHTTPWatchers(ctx context.Context) {
	if s.cfg == nil || !s.cfg.Modules.Watch.Enabled {
		return
	}
	for _, fw := range s.cfg.Modules.Watch.Files {
		go s.watchFile(ctx, fw)
	}
	for _, hw := range s.cfg.Modules.Watch.HTTP {
		go s.watchHTTP(ctx, hw)
	}
}

// watchFile tails a file (poll-based, no fsnotify dependency) and notifies on
// each newly-appended line that matches the configured regexp.
func (s *Server) watchFile(ctx context.Context, fw config.FileWatch) {
	re, err := regexp.Compile(fw.Grep)
	if err != nil {
		slog.Warn("daemon: invalid file-watch regexp; skipping", "path", fw.Path, "grep", fw.Grep, "err", err)
		return
	}
	label := fw.Label
	if label == "" {
		label = fw.Path
	}

	poll := filePollInterval
	if fw.PollSecs > 0 {
		poll = time.Duration(fw.PollSecs) * time.Second
	}

	var offset int64
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		offset = s.scanFileFrom(ctx, fw.Path, offset, re, label)
	}
}

// scanFileFrom reads new lines from offset, notifies on matches, and returns the
// new offset. A shrunk file (rotation/truncation) resets the offset to 0.
func (s *Server) scanFileFrom(ctx context.Context, path string, offset int64, re *regexp.Regexp, label string) int64 {
	f, err := os.Open(path) //nolint:gosec // path is operator-configured
	if err != nil {
		return offset
	}
	defer func() { _ = f.Close() }()

	if info, statErr := f.Stat(); statErr == nil && info.Size() < offset {
		offset = 0 // file was truncated/rotated
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}

	scanner := bufio.NewScanner(f)
	// NET-11: enlarge the scanner buffer past bufio's 64 KiB default so long
	// log lines do not poison the watcher.
	scanner.Buffer(make([]byte, 64*1024), maxScanLine)
	for scanner.Scan() {
		line := scanner.Text()
		offset += int64(len(line)) + 1
		if !re.MatchString(line) {
			continue
		}
		body := line
		if len(body) > maxBodyLine {
			body = body[:maxBodyLine]
		}
		if err := s.notifier.Send(ctx, "watch: "+label, body); err != nil {
			slog.Warn("daemon: file watcher notify failed", "path", path, "err", err)
		}
	}
	// NET-11: a scan error (line > maxScanLine, read error) used to be silently
	// ignored — the offset never advanced past the poison line, stalling the
	// watcher forever. Log it and skip to the current end of file so the
	// watcher recovers and keeps tailing subsequent appends.
	if err := scanner.Err(); err != nil {
		slog.Warn("daemon: file watcher scan error; skipping to end of file to recover",
			"path", path, "err", err)
		if end, seekErr := f.Seek(0, io.SeekEnd); seekErr == nil {
			return end
		}
	}
	return offset
}

// watchHTTP polls a URL and notifies when its status code changes from the
// expected (or previously seen) value. Transport failures are an explicit
// "unreachable" state with the error logged (NET-17) — never conflated with a
// fabricated "HTTP status 0".
func (s *Server) watchHTTP(ctx context.Context, hw config.HTTPWatch) {
	interval := defaultHTTPInterval
	if hw.IntervalSecs > 0 {
		interval = time.Duration(hw.IntervalSecs) * time.Second
	}
	label := hw.Label
	if label == "" {
		label = hw.URL
	}
	client := &http.Client{Timeout: 10 * time.Second}
	last := hw.Expect
	// baselined distinguishes "no baseline yet" (Expect unset; adopt the first
	// probe result silently) from "previously unreachable" (code 0 after a
	// transport failure). Without it, a recovery after an outage would be
	// swallowed as a new baseline (NET-17).
	baselined := hw.Expect != 0

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		code := 0
		var probeErr error
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, hw.URL, nil)
		if err != nil {
			probeErr = err
		} else if resp, derr := client.Do(req); derr != nil {
			probeErr = derr
		} else {
			code = resp.StatusCode
			// Drain before Close so the keep-alive connection is reusable (NET-17).
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		if probeErr != nil {
			// NET-17: log the transport error detail; the notification below
			// reports an explicit unreachable state, not a fake status code.
			slog.Warn("daemon: http watcher probe failed", "url", hw.URL, "err", probeErr)
		}
		if !baselined {
			last = code
			baselined = true
			continue
		}
		if code != last {
			var msg string
			switch {
			case code == 0:
				msg = fmt.Sprintf("%s: unreachable (was HTTP %d)", label, last)
			case last == 0:
				msg = fmt.Sprintf("%s: reachable again (HTTP %d)", label, code)
			default:
				msg = fmt.Sprintf("%s: HTTP status changed %d → %d", label, last, code)
			}
			if err := s.notifier.Send(ctx, "watch: "+label, msg); err != nil {
				slog.Warn("daemon: http watcher notify failed", "url", hw.URL, "err", err)
			}
			last = code
		}
	}
}
