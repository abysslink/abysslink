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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// Watcher polling defaults. The pane watcher fires when a pane has shown a
// prompt-shaped last line with no output change for at least idleInterval.
const (
	panePollInterval = 5 * time.Second
	paneIdleInterval = 30 * time.Second
	paneCoolOff      = 5 * time.Minute
	readHeaderTO     = 5 * time.Second
)

// promptRegex matches common shell/REPL prompt-shaped trailing lines.
var promptRegex = regexp.MustCompile(`[>$?#»❯]\s*$`)

// Server serves the notify socket and runs configured watchers.
type Server struct {
	notifier   Notifier
	runner     shell.Runner
	cfg        *config.Config
	socketPath string
}

// NewServer returns a Server. notifier MUST be a direct backend (see Notifier).
func NewServer(notifier Notifier, runner shell.Runner, cfg *config.Config) *Server {
	return &Server{notifier: notifier, runner: runner, cfg: cfg, socketPath: SocketPath()}
}

// Run listens on the Unix socket and starts watchers until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("daemon: clear stale socket: %w", err)
	}
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("daemon: listen %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("daemon: chmod socket: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/notify", s.handleNotify)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: readHeaderTO}

	s.startWatchers(ctx)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = os.Remove(s.socketPath)
	}()

	slog.Info("abysslinkd listening", "socket", s.socketPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("daemon: serve: %w", err)
	}
	return nil
}

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req NotifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		http.Error(w, "title is required", http.StatusBadRequest)
		return
	}
	if err := s.notifier.Send(r.Context(), req.Title, req.Body); err != nil {
		slog.Warn("daemon: notify delivery failed", "err", err)
		http.Error(w, "delivery failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// startWatchers launches a goroutine per configured tmux pane watcher.
func (s *Server) startWatchers(ctx context.Context) {
	if s.cfg == nil || !s.cfg.Modules.Watch.Enabled {
		return
	}
	for _, pane := range s.cfg.Modules.Watch.Panes {
		go s.watchPane(ctx, pane)
	}
}

// watchPane polls a tmux pane and notifies when it has been idle at a prompt.
func (s *Server) watchPane(ctx context.Context, pane string) {
	ticker := time.NewTicker(panePollInterval)
	defer ticker.Stop()

	var lastHash string
	var idleSince, lastNotified time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		res, err := s.runner.Run(ctx, "tmux", "capture-pane", "-t", pane, "-p")
		if err != nil || res.ExitCode != 0 {
			continue
		}
		sum := fmt.Sprintf("%x", sha256.Sum256([]byte(res.Stdout)))
		now := time.Now()
		if sum != lastHash {
			lastHash = sum
			idleSince = now
			continue
		}
		if now.Sub(idleSince) < paneIdleInterval || now.Sub(lastNotified) < paneCoolOff {
			continue
		}
		if !promptRegex.MatchString(lastNonEmptyLine(res.Stdout)) {
			continue
		}
		if err := s.notifier.Send(ctx, "waiting for input", fmt.Sprintf("tmux pane %q is idle at a prompt", pane)); err != nil {
			slog.Warn("daemon: pane watcher notify failed", "pane", pane, "err", err)
			continue
		}
		lastNotified = now
	}
}

// lastNonEmptyLine returns the last non-blank line of s.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}
