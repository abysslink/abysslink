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

package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendDirect_PostsToNtfy(t *testing.T) {
	var receivedTitle, receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTitle = r.Header.Get("X-Title")
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirect(context.Background(), "hello title", "hello body")
	require.NoError(t, err)
	assert.Equal(t, "hello title", receivedTitle)
	assert.Equal(t, "hello body", receivedBody)
}

func TestSendDirect_NonOKStatus_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad credentials"))
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirect(context.Background(), "t", "b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

// ── CLI-04: SendDirectWithOptions threads priority / tags / topic ────────────

// TestSendDirectWithOptions_HeadersAndTopic verifies that priority and tags
// become the ntfy X-Priority / X-Tags headers and that the topic override
// replaces the configured default topic in the URL path.
func TestSendDirectWithOptions_HeadersAndTopic(t *testing.T) {
	var gotPath, gotPriority, gotTags string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPriority = r.Header.Get("X-Priority")
		gotTags = r.Header.Get("X-Tags")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{
		Priority: "high",
		Tags:     "warning",
		Topic:    "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, "/ops", gotPath, "--topic must override the configured default topic")
	assert.Equal(t, "high", gotPriority, "--priority must be sent as X-Priority")
	assert.Equal(t, "warning", gotTags, "--tag must be sent as X-Tags")
}

// TestSendDirectWithOptions_ZeroValueBackCompat verifies that zero options
// behave exactly like the historical SendDirect: default topic, no
// X-Priority/X-Tags headers.
func TestSendDirectWithOptions_ZeroValueBackCompat(t *testing.T) {
	var gotPath, gotPriority, gotTags string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPriority = r.Header.Get("X-Priority")
		gotTags = r.Header.Get("X-Tags")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	require.NoError(t, m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{}))
	assert.Equal(t, "/alerts", gotPath, "zero options must use the configured default topic")
	assert.Empty(t, gotPriority, "zero options must not set X-Priority")
	assert.Empty(t, gotTags, "zero options must not set X-Tags")
}

// TestSendDirectWithOptions_ClickHeader verifies that SendOptions.Click becomes
// the ntfy X-Click header (D-16: tap-to-open ssh:// deep link) and that an
// empty Click sets no header at all.
func TestSendDirectWithOptions_ClickHeader(t *testing.T) {
	var gotClick string
	var clickPresent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClick = r.Header.Get("X-Click")
		_, clickPresent = r.Header["X-Click"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{
		Click: "ssh://mo@rig-1",
	})
	require.NoError(t, err)
	assert.True(t, clickPresent, "non-empty Click must set the X-Click header")
	assert.Equal(t, "ssh://mo@rig-1", gotClick, "X-Click must carry the exact configured value")

	// Empty Click → no X-Click header.
	require.NoError(t, m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{}))
	assert.False(t, clickPresent, "empty Click must not set X-Click")
}

// TestSendWithOptions_ZeroValueGuardStillComparable verifies that adding the
// Click string field keeps SendOptions comparable so the zero-options fast-path
// guard in SendWithOptions (opts == SendOptions{}) still compiles and works.
func TestSendWithOptions_ZeroValueGuardStillComparable(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	// Comparability is compile-level: SendWithOptions' own
	// `opts == (SendOptions{})` guard would not build if the Click field
	// broke it. Behavioral: zero options still deliver via the direct
	// fallback to the configured default topic (no daemon is listening).
	require.NoError(t, m.SendWithOptions(context.Background(), "t", "b", SendOptions{}))
	assert.Equal(t, "/alerts", gotPath)
}

// TestSendDirectWithOptions_InvalidTopicRejected verifies that a topic override
// outside the ntfy topic charset is refused before any request is built (the
// override is a URL path segment — it must never alter the request path).
func TestSendDirectWithOptions_InvalidTopicRejected(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{Topic: "../evil"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid topic")
}
