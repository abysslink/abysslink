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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Notifier delivers a notification to the phone. The daemon depends on this
// interface rather than the notify module so there is no import cycle. The
// implementation passed to the server MUST be the direct backend (not the
// socket-aware Send) or notifications would loop back into the daemon.
type Notifier interface {
	Send(ctx context.Context, title, body string) error
}

// NotifyRequest is the JSON body accepted by POST /notify.
type NotifyRequest struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Topic    string `json:"topic,omitempty"`
	Priority string `json:"priority,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

// SocketPath returns the path to the abysslinkd Unix socket. It prefers
// XDG_RUNTIME_DIR (Linux); on macOS, which has no such dir, it uses a private
// per-user directory under the OS temp dir.
//
// NET-13: the fallback directory lives under the world-writable OS temp dir, so
// a local attacker could pre-create it and own the socket dir (intercepting or
// squatting the daemon socket). socketPath verifies the directory after
// creation; on any verification failure SocketPath fails closed by returning ""
// (callers cannot bind or dial an empty path) and logs the reason via slog.
func SocketPath() string {
	p, err := socketPath()
	if err != nil {
		slog.Error("daemon: socket directory verification failed; failing closed", "err", err)
		return ""
	}
	return p
}

// socketPath resolves the socket path, verifying the macOS/no-XDG fallback
// directory (create, then Lstat-verify: not a symlink, a directory, owned by
// the current uid, mode 0700). The XDG_RUNTIME_DIR path is OS-managed and
// already per-user 0700; it is used as-is.
func socketPath() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("abysslink-%d", os.Getuid()))
		if err := ensurePrivateDir(base); err != nil {
			return "", err
		}
	}
	return filepath.Join(base, "abysslinkd.sock"), nil
}

// ensurePrivateDir creates dir (0700) and fails closed unless it is a real
// directory (not a symlink) owned by the current uid with mode exactly 0700
// (NET-13). A pre-existing path that fails any check is a clear error — never
// silently accepted.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: create socket dir %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("daemon: lstat socket dir %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("daemon: socket dir %s is a symlink — refusing (possible local-attacker squat, NET-13)", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("daemon: socket path %s exists but is not a directory — refusing (NET-13)", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("daemon: cannot verify socket dir ownership on this platform — refusing (NET-13)")
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("daemon: socket dir %s is owned by uid %d, not current uid %d — refusing (possible local-attacker squat, NET-13)",
			dir, st.Uid, os.Getuid())
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return fmt.Errorf("daemon: socket dir %s has mode %04o, want 0700 — refusing (NET-13)", dir, perm)
	}
	return nil
}

// Client talks to a running abysslinkd over its Unix socket.
type Client struct {
	socketPath string
	httpClient *http.Client
}

// NewClient returns a Client for the default socket path.
func NewClient() *Client {
	sp := SocketPath()
	return &Client{
		socketPath: sp,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sp)
				},
			},
		},
	}
}

// Send delivers req via the daemon socket. It returns an error if the daemon is
// not running or rejects the request; callers fall back to a direct backend.
func (c *Client) Send(ctx context.Context, req NotifyRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("daemon client: marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/notify", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("daemon client: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("daemon client: socket unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("daemon client: notify returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Ping reports whether a daemon is listening and healthy.
func (c *Client) Ping(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}
