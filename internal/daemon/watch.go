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

	var offset int64
	ticker := time.NewTicker(filePollInterval)
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
	return offset
}

// watchHTTP polls a URL and notifies when its status code changes from the
// expected (or previously seen) value.
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

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		code := 0
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, hw.URL, nil)
		if err == nil {
			if resp, derr := client.Do(req); derr == nil {
				code = resp.StatusCode
				_ = resp.Body.Close()
			}
		}
		if last == 0 {
			last = code
			continue
		}
		if code != last {
			msg := fmt.Sprintf("%s: HTTP status changed %d → %d", label, last, code)
			if err := s.notifier.Send(ctx, "watch: "+label, msg); err != nil {
				slog.Warn("daemon: http watcher notify failed", "url", hw.URL, "err", err)
			}
			last = code
		}
	}
}
