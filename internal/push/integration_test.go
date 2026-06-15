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

//go:build integration
// +build integration

// Package push_test contains the real-device integration test for the
// push-gateway → tailnet-fetch → ack loop (SC#1 / D-20). Run manually:
//
//	go test -tags integration ./internal/push/... -run TestRealDevicePush -v -timeout 120s
//
// See docs/testing/push-real-device.md for prerequisites, env var setup,
// Doze test procedure, and how to record results in the SUMMARY.
package push_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEnv holds the environment variables for the real-device test.
// All values are sourced from env at test start; none are stored in code.
type testEnv struct {
	ntfyEndpoint string // PUSH_TEST_NTFY_ENDPOINT — the enrolled device's UnifiedPush endpoint URL
	deviceID     string // PUSH_TEST_DEVICE_ID — enrolled device ULID
	daemonSocket string // PUSH_TEST_DAEMON_SOCKET — optional override of daemon.SocketPath()
}

// loadTestEnv reads the required env vars. Returns (env, false) if any
// required var is absent — callers must skip the test in that case.
func loadTestEnv() (testEnv, bool) {
	e := testEnv{
		ntfyEndpoint: os.Getenv("PUSH_TEST_NTFY_ENDPOINT"),
		deviceID:     os.Getenv("PUSH_TEST_DEVICE_ID"),
		daemonSocket: os.Getenv("PUSH_TEST_DAEMON_SOCKET"),
	}
	if e.ntfyEndpoint == "" || e.deviceID == "" {
		return e, false
	}
	if e.daemonSocket == "" {
		e.daemonSocket = daemon.SocketPath()
	}
	return e, true
}

// daemonHTTPClient returns an *http.Client that dials the daemon's unix socket.
func daemonHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// daemonStatusCounters fetches the gateway counters from GET /status on the
// daemon socket and returns the raw JSON map. Any error is returned directly.
func daemonStatusCounters(ctx context.Context, socketPath string) (map[string]interface{}, error) {
	client := daemonHTTPClient(socketPath)
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/status", nil)
	if err != nil {
		return nil, fmt.Errorf("build status request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /status returned HTTP %d", resp.StatusCode)
	}
	var m map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode /status: %w", err)
	}
	return m, nil
}

// postNotifyV2 sends a v2 notify message to the daemon's POST /notify endpoint
// and returns any error.
func postNotifyV2(ctx context.Context, socketPath, deviceID string) error {
	client := daemonHTTPClient(socketPath)
	defer client.CloseIdleConnections()

	// Minimal v2 wake message — routing metadata only (opaque-wake invariant).
	payload := map[string]interface{}{
		"kind":       "generic_notification",
		"device_id":  deviceID,
		"title":      "abysslink integration test wake",
		"session_id": "integration-test-session",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal notify payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/notify",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build notify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /notify: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("POST /notify returned HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// getUint64Field extracts a uint64 value from a JSON map by key. Returns 0
// when the key is absent or the value is not a JSON number.
func getUint64Field(m map[string]interface{}, key string) uint64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return uint64(n) //nolint:gosec // G115: JSON numbers decoded as float64, value is non-negative counter
	default:
		return 0
	}
}

// TestRealDevicePush exercises the full opaque-wake → tailnet-fetch → ack loop
// on real hardware (D-20 / SC#1):
//
//  1. Reads gateway counters from GET /status (baseline).
//  2. Sends a v2 notify wake via POST /notify to the daemon.
//  3. Asserts gateway_queued and gateway_sent are non-zero (automated portion).
//  4. Documents the expected manual verification steps (screen-on, ack).
//
// The actual visual verification (phone screen wakes, notification visible,
// ack_received increments) requires a human observer; see the runbook in
// docs/testing/push-real-device.md.
//
// Environment variables (required):
//   - PUSH_TEST_NTFY_ENDPOINT — the ntfy endpoint URL the enrolled phone subscribes to
//   - PUSH_TEST_DEVICE_ID     — the enrolled device ULID (from `abysslink device list`)
//
// Optional:
//   - PUSH_TEST_DAEMON_SOCKET — override daemon socket path (defaults to daemon.SocketPath())
func TestRealDevicePush(t *testing.T) {
	env, ok := loadTestEnv()
	if !ok {
		t.Skip("PUSH_TEST_NTFY_ENDPOINT and PUSH_TEST_DEVICE_ID not set — " +
			"set env vars and run with -tags integration (see docs/testing/push-real-device.md)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	t.Log("=== Real-device push integration test (SC#1 / D-20) ===")
	t.Log("Test flow:")
	t.Log("  1. Snapshot gateway counters from daemon /status")
	t.Log("  2. POST wake to daemon /notify")
	t.Log("  3. Assert gateway_queued + gateway_sent incremented (automated)")
	t.Log("  4. MANUAL: observe phone wakes, notification visible, tapping fetches content over tailnet")
	t.Log("  5. MANUAL: verify ack_received increments in `abysslink status`")
	t.Logf("  Device ID:    %s", env.deviceID)
	t.Logf("  Daemon socket: %s", env.daemonSocket)
	// NOTE: ntfy endpoint URL is NOT logged — it is a secret-class value (D-17).

	// Step 1: baseline counters.
	baseline, err := daemonStatusCounters(ctx, env.daemonSocket)
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("daemon /status timed out — is abysslinkd running?")
	}
	require.NoError(t, err, "GET /status must succeed — is abysslinkd running on socket %s?", env.daemonSocket)
	baseQueued := getUint64Field(baseline, "gateway_queued")
	baseSent := getUint64Field(baseline, "gateway_sent")
	baseAccepted := getUint64Field(baseline, "gateway_provider_accepted")
	t.Logf("Baseline counters: gateway_queued=%d gateway_sent=%d gateway_provider_accepted=%d",
		baseQueued, baseSent, baseAccepted)

	// Step 2: send a wake.
	t.Log("Sending v2 wake via POST /notify ...")
	require.NoError(t, postNotifyV2(ctx, env.daemonSocket, env.deviceID),
		"POST /notify must succeed")
	t.Log("Wake posted. Waiting up to 30s for outbox retry goroutine to dispatch ...")

	// Step 3: poll /status until gateway_queued increments (outbox entry written)
	// and gateway_sent increments (dispatch attempted). The retry loop fires every
	// 5 seconds; 30 seconds gives ≥5 opportunities.
	var afterQueued, afterSent uint64
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		after, serr := daemonStatusCounters(ctx, env.daemonSocket)
		if serr != nil {
			t.Logf("  /status poll failed (transient): %v", serr)
			time.Sleep(2 * time.Second)
			continue
		}
		afterQueued = getUint64Field(after, "gateway_queued")
		afterSent = getUint64Field(after, "gateway_sent")
		if afterQueued > baseQueued {
			break
		}
		time.Sleep(2 * time.Second)
	}

	assert.Greater(t, afterQueued, baseQueued,
		"gateway_queued must have incremented — outbox entry was not written")
	t.Logf("After send: gateway_queued=%d (+%d) gateway_sent=%d (+%d)",
		afterQueued, afterQueued-baseQueued,
		afterSent, afterSent-baseSent)

	// Step 4: manual verification instructions (recorded in the test log).
	t.Log("")
	t.Log("=== MANUAL VERIFICATION REQUIRED ===")
	t.Log("1. Observe phone: screen should wake and show a push notification.")
	t.Log("2. Tap the notification: the deep link should open and fetch content over the tailnet.")
	t.Log("3. Run `abysslink status` and verify ack_received has incremented.")
	t.Log("4. For Doze test: run `adb shell dumpsys deviceidle force-idle` before step 2.")
	t.Log("   The phone must wake within 60 seconds of the push dispatch.")
	t.Log("5. Record the outcome (device model, Android version, ntfy version,")
	t.Log("   Doze behaviour) in .planning/phases/29-push-gateway-outbox/29-05-SUMMARY.md.")
}
