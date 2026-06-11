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
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatusDaemonExtras_DecodeNewDaemon covers the defensive decode of a
// daemon that emits the BACK-07/DEVC-04 fields (plus unknown fields, which
// must be ignored).
func TestStatusDaemonExtras_DecodeNewDaemon(t *testing.T) {
	body := `{
		"version": "v3", "backend": "tailscale", "uptime": "1h",
		"wake_sent": 7, "ack_received": 3,
		"content_store": "ready",
		"devices": [
			{"name": "phone", "last_seen": "2026-06-01T12:00:00Z", "stale": false, "revoked": false},
			{"name": "tablet", "stale": true},
			{"name": "old", "revoked": true}
		],
		"some_future_field": {"nested": true}
	}`
	var ex statusDaemonExtras
	require.NoError(t, json.Unmarshal([]byte(body), &ex))
	require.NotNil(t, ex.WakeSent)
	assert.Equal(t, uint64(7), *ex.WakeSent)
	require.NotNil(t, ex.AckReceived)
	assert.Equal(t, uint64(3), *ex.AckReceived)
	assert.Equal(t, "ready", contentStoreLabel(ex.ContentStore))
	require.Len(t, ex.Devices, 3)
	assert.Equal(t, "phone", ex.Devices[0].Name)
	assert.True(t, ex.Devices[1].Stale)
	assert.True(t, ex.Devices[2].Revoked)

	var rep statusReport
	applyStatusExtras(&rep, &ex, nil)
	assert.Equal(t, ex.WakeSent, rep.WakeSent)
	assert.Equal(t, ex.AckReceived, rep.AckReceived)
	assert.Len(t, rep.Devices, 3)
}

// TestStatusDaemonExtras_OlderDaemonOmits covers an older daemon whose /status
// lacks the new fields entirely: the section is omitted, never an error, and
// the JSON report carries none of the new keys.
func TestStatusDaemonExtras_OlderDaemonOmits(t *testing.T) {
	body := `{"version": "v2", "backend": "tailscale", "reachable": true, "uptime": "5m"}`
	var ex statusDaemonExtras
	require.NoError(t, json.Unmarshal([]byte(body), &ex))

	rep := statusReport{Tailscale: "running", Timestamp: "2026-06-01T12:00:00Z"}
	applyStatusExtras(&rep, &ex, nil)
	assert.Nil(t, rep.WakeSent)
	assert.Nil(t, rep.AckReceived)
	assert.Empty(t, rep.ContentStore)
	assert.Empty(t, rep.Devices)

	// JSON pass-through: omitted fields must not appear at all.
	out, err := json.Marshal(rep)
	require.NoError(t, err)
	for _, key := range []string{"wake_sent", "ack_received", "content_store", "devices"} {
		assert.NotContains(t, string(out), key, "an older daemon must not surface a zeroed %s", key)
	}

	// Human rendering: nothing printed for an all-absent extras section.
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, io.Discard)
	renderStatusExtras(p, rep, time.Now())
	assert.Empty(t, buf.String(), "absent extras must render nothing")
}

// TestStatusDaemonExtras_FallbackLocalStore covers the daemon-unreachable
// path: the device list is read straight from the local device store, so
// enrollment state stays visible without abysslinkd (DEVC-04).
func TestStatusDaemonExtras_FallbackLocalStore(t *testing.T) {
	ctx := context.Background()
	st, dir := newTestDeviceStore(t, nil)
	_, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	overrideDeviceStorePath(t, filepath.Join(dir, "devices.json"))

	var rep statusReport
	applyStatusExtras(&rep, nil, errors.New("dial unix: no such file"))

	assert.Nil(t, rep.WakeSent, "wake/ack counters are daemon-only and stay omitted")
	require.Len(t, rep.Devices, 1, "devices must be read from the local store on fallback")
	assert.Equal(t, "phone", rep.Devices[0].Name)
	assert.False(t, rep.Devices[0].Stale)
	assert.False(t, rep.Devices[0].Revoked)
	assert.Empty(t, rep.Devices[0].LastSeen, "never-seen device omits last_seen")
}

// TestStatusDaemonExtras_FallbackEmptyStore: daemon unreachable and nothing
// enrolled — the section stays omitted (current behavior preserved).
func TestStatusDaemonExtras_FallbackEmptyStore(t *testing.T) {
	overrideDeviceStorePath(t, filepath.Join(t.TempDir(), "devices.json"))
	var rep statusReport
	applyStatusExtras(&rep, nil, errors.New("daemon unreachable"))
	assert.Empty(t, rep.Devices)
}

// TestRenderStatusExtras_Human covers the BACK-07/DEVC-04 human lines: the
// wake/ack counter line, the content-store line, and the device block with
// stale (⚠, humanized last-seen) and revoked flags.
func TestRenderStatusExtras_Human(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	wake, ack := uint64(2), uint64(1)
	rep := statusReport{
		WakeSent:     &wake,
		AckReceived:  &ack,
		ContentStore: json.RawMessage(`"ready"`),
		Devices: []statusDeviceEntry{
			{Name: "phone", LastSeen: now.Add(-2 * time.Minute).Format(time.RFC3339)},
			{Name: "tablet", LastSeen: now.Add(-9 * 24 * time.Hour).Format(time.RFC3339), Stale: true},
			{Name: "watch", Stale: true},
			{Name: "old", Revoked: true},
		},
	}

	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, io.Discard)
	renderStatusExtras(p, rep, now)
	got := stripANSI(buf.String())

	assert.Contains(t, got, "notifications: 2 wakes sent · 1 acks received")
	assert.Contains(t, got, "content store: ready")
	assert.Contains(t, got, "phone  last seen 2m ago")
	assert.Contains(t, got, "tablet  ⚠ stale — last seen 9d ago")
	assert.Contains(t, got, "watch  ⚠ stale — never checked in")
	assert.Contains(t, got, "old  revoked")
}

// TestRenderStatusExtras_ContentStoreObject covers the defensive content_store
// rendering: a non-string shape is shown as raw JSON, never an error.
func TestRenderStatusExtras_ContentStoreObject(t *testing.T) {
	rep := statusReport{ContentStore: json.RawMessage(`{"state":"ok","entries":4}`)}
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, io.Discard)
	renderStatusExtras(p, rep, time.Now())
	assert.Contains(t, stripANSI(buf.String()), `content store: {"state":"ok","entries":4}`)
}

// TestStatusReport_JSONPassThrough covers the --json contract: the daemon's
// fields pass through under their own keys.
func TestStatusReport_JSONPassThrough(t *testing.T) {
	wake, ack := uint64(5), uint64(4)
	rep := statusReport{
		Tailscale:    "running",
		WakeSent:     &wake,
		AckReceived:  &ack,
		ContentStore: json.RawMessage(`"ready"`),
		Devices:      []statusDeviceEntry{{Name: "phone", Stale: true}},
	}
	out, err := json.Marshal(rep)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(out, &decoded))
	assert.EqualValues(t, 5, decoded["wake_sent"])
	assert.EqualValues(t, 4, decoded["ack_received"])
	assert.Equal(t, "ready", decoded["content_store"])
	devs, ok := decoded["devices"].([]any)
	require.True(t, ok)
	require.Len(t, devs, 1)
}

// TestLastSeenLabel covers the humanized last-seen rendering, including the
// defensive verbatim path for an unparseable daemon value.
func TestLastSeenLabel(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, "never", lastSeenLabel("", now))
	assert.Equal(t, "just now", lastSeenLabel(now.Add(-10*time.Second).Format(time.RFC3339), now))
	assert.Equal(t, "5m ago", lastSeenLabel(now.Add(-5*time.Minute).Format(time.RFC3339), now))
	assert.Equal(t, "3h ago", lastSeenLabel(now.Add(-3*time.Hour).Format(time.RFC3339), now))
	assert.Equal(t, "9d ago", lastSeenLabel(now.Add(-9*24*time.Hour).Format(time.RFC3339), now))
	assert.Equal(t, "not-a-time", lastSeenLabel("not-a-time", now), "unparseable values are shown verbatim")
}
