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

package daemon_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortRuntimeDir returns a short XDG_RUNTIME_DIR. macOS limits Unix socket
// paths to ~104 bytes, and t.TempDir() under /var/folders is too long, so we
// use a short /tmp-based dir.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type fakeNotifier struct {
	mu    sync.Mutex
	title string
	body  string
	calls int
}

func (f *fakeNotifier) Send(_ context.Context, title, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.title, f.body, f.calls = title, body, f.calls+1
	return nil
}

func (f *fakeNotifier) SendNote(_ context.Context, _ notifyv2.RenderedNote) error { return nil }

func (f *fakeNotifier) last() (string, string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.title, f.body, f.calls
}

func TestServer_NotifySocketRoundTrip(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", shortRuntimeDir(t))

	fn := &fakeNotifier{}
	cfg := config.Defaults()
	cfg.Modules.Watch.Enabled = false // no tmux calls in this test

	srv := daemon.NewServer(fn, shell.NewMockRunner(), cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	client := daemon.NewClient()
	require.Eventually(t, func() bool { return client.Ping(context.Background()) },
		2*time.Second, 20*time.Millisecond, "daemon socket should come up")

	require.NoError(t, client.Send(context.Background(), daemon.NotifyRequest{Title: "hi", Body: "there"}))
	require.Eventually(t, func() bool {
		title, body, calls := fn.last()
		return calls == 1 && title == "hi" && body == "there"
	}, time.Second, 10*time.Millisecond, "notifier should receive the forwarded message")

	// A request with no title is rejected.
	err := client.Send(context.Background(), daemon.NotifyRequest{Body: "no title"})
	assert.Error(t, err)
}

func TestClient_PingFailsWhenNoDaemon(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", shortRuntimeDir(t))
	assert.False(t, daemon.NewClient().Ping(context.Background()))
}
