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
	"net"
	"net/http"
	"os"
	"path/filepath"
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
func SocketPath() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("abysslink-%d", os.Getuid()))
		_ = os.MkdirAll(base, 0o700)
	}
	return filepath.Join(base, "abysslinkd.sock")
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
