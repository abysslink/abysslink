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

package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListEvents_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/events/audit", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]nbAuditEvent{
			{ID: "e1", Activity: "peer.login"},
			{ID: "e2", Activity: "peer.add"},
		})
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	events, err := a.ListEvents(context.Background())
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "e1", events[0].ID)
}

func TestListEvents_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	_, err := a.ListEvents(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}

// TestTailEvents_Once verifies that without follow, TailEvents fetches once and
// writes each event as a JSON line.
func TestTailEvents_Once(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]nbAuditEvent{
			{ID: "e1", Activity: "peer.login"},
			{ID: "e2", Activity: "peer.add"},
		})
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	var buf bytes.Buffer
	err := a.TailEvents(context.Background(), &buf, false)
	require.NoError(t, err)
	lines := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
	assert.Equal(t, 2, lines, "expected one JSON line per event")
	assert.Contains(t, buf.String(), "e1")
	assert.Contains(t, buf.String(), "e2")
}

// TestTailEvents_Follow_Deduplicates verifies that follow mode polls more than
// once but only prints each event a single time when the watermark is unchanged.
func TestTailEvents_Follow_Deduplicates(t *testing.T) {
	var polls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&polls, 1)
		w.WriteHeader(http.StatusOK)
		// Always return the same two events on every poll.
		_ = json.NewEncoder(w).Encode([]nbAuditEvent{
			{ID: "e1", Activity: "peer.login"},
			{ID: "e2", Activity: "peer.add"},
		})
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	// Override backoff to be fast so the test runs quickly.
	a.eventPollStart = 10 * time.Millisecond
	a.eventPollMax = 20 * time.Millisecond

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	err := a.TailEvents(ctx, &buf, true)
	require.NoError(t, err)
	// The server should have been polled at least twice.
	assert.GreaterOrEqual(t, atomic.LoadInt32(&polls), int32(2), "follow mode should poll repeatedly")
	// e1 should appear exactly once despite multiple polls.
	assert.Equal(t, 1, strings.Count(buf.String(), `"e1"`), "watermark must prevent duplicate output")
	assert.Equal(t, 1, strings.Count(buf.String(), `"e2"`))
}

// TestTailEvents_Follow_Cancellation verifies clean exit on context cancellation.
func TestTailEvents_Follow_Cancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]nbAuditEvent{{ID: "e1", Activity: "peer.login"}})
	}))
	defer srv.Close()

	a := newTestNetBirdAdapter(t, srv.URL)
	a.eventPollStart = 10 * time.Millisecond
	a.eventPollMax = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- a.TailEvents(ctx, &buf, true) }()
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "cancellation must produce a clean nil return")
	case <-time.After(2 * time.Second):
		t.Fatal("TailEvents did not exit on context cancellation")
	}
}
