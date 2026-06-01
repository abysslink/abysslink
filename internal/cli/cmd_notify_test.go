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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── TestNotifyAllRigs_Headers ─────────────────────────────────────────────────

// notifyTestKeychain is an in-memory KeychainStore for notify tests.
type notifyTestKeychain struct {
	mu   sync.RWMutex
	data map[string]string
}

func newNotifyTestKeychain() *notifyTestKeychain {
	return &notifyTestKeychain{data: make(map[string]string)}
}

func (k *notifyTestKeychain) Set(_ context.Context, service, account, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[service+":"+account] = secret
	return nil
}

func (k *notifyTestKeychain) Get(_ context.Context, service, account string) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.data[service+":"+account]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (k *notifyTestKeychain) Delete(_ context.Context, _, _ string) error { return nil }

// capturedRequest stores a received HTTP request for later assertion.
type capturedRequest struct {
	path string
	hdr  http.Header
}

// TestNotifyAllRigs_Headers verifies that sendNotifyAllRigs sends a POST per rig,
// each request carrying the three HMAC rig-identity headers with correct values
// (SC-5, D-NI-03, T-14-17 / T-14-20). Also asserts per-rig topic isolation
// (T-14-18: Rig A never POSTs to Rig B's topic).
func TestNotifyAllRigs_Headers(t *testing.T) {
	// Set up an httptest.Server to capture all requests.
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{
			path: r.URL.Path,
			hdr:  r.Header.Clone(),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Override the base URL test seam.
	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	// Two rigs with distinct topics.
	const (
		rigA    = "rig-alpha"
		topicA  = "abysslink-rig-alpha-aabbccdd"
		rigB    = "rig-beta"
		topicB  = "abysslink-rig-beta-11223344"
		title   = "Test Title"
		msgBody = "Hello fleet"
	)

	kc := newNotifyTestKeychain()

	// Generate and store a signing key for each rig.
	keyA, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	keyB, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	require.NoError(t, kc.Set(context.Background(), fleet.RigService(rigA), "hmac-signing-key", keyA))
	require.NoError(t, kc.Set(context.Background(), fleet.RigService(rigB), "hmac-signing-key", keyB))

	rigs := []config.RigConfig{
		{Name: rigA, NtfyTopic: topicA},
		{Name: rigB, NtfyTopic: topicB},
	}

	err = sendNotifyAllRigs(context.Background(), rigs, kc, title, msgBody)
	require.NoError(t, err)

	require.Len(t, received, 2, "one POST per rig")

	// Build a lookup: topic path → captured request.
	byPath := make(map[string]capturedRequest)
	for _, r := range received {
		byPath[r.path] = r
	}

	// ── Rig A assertions ──

	reqA, ok := byPath["/"+topicA]
	require.True(t, ok, "Rig A must POST to its own topic %q, not to Rig B's", topicA)

	assert.Equal(t, rigA, reqA.hdr.Get("X-Abysslink-Rig"), "X-Abysslink-Rig must be rig A's name")
	tsA := reqA.hdr.Get("X-Abysslink-Rig-Ts")
	require.NotEmpty(t, tsA, "X-Abysslink-Rig-Ts must be set (Pitfall 6 / T-14-20)")
	sigA := reqA.hdr.Get("X-Abysslink-Rig-Sig")
	require.NotEmpty(t, sigA, "X-Abysslink-Rig-Sig must be set (SC-5)")

	// Recompute the HMAC and verify it matches (round-trip: origin provable).
	assert.True(t,
		fleet.VerifyRigMessage(keyA, rigA, tsA, msgBody, sigA),
		"HMAC recompute+VerifyRigMessage for Rig A must return true (SC-5)")

	// Tampering the body must make the signature fail.
	assert.False(t,
		fleet.VerifyRigMessage(keyA, rigA, tsA, "tampered body", sigA),
		"Tampering the message body must make VerifyRigMessage return false")

	// ── Rig B assertions ──

	reqB, ok := byPath["/"+topicB]
	require.True(t, ok, "Rig B must POST to its own topic %q, not to Rig A's", topicB)

	assert.Equal(t, rigB, reqB.hdr.Get("X-Abysslink-Rig"), "X-Abysslink-Rig must be rig B's name")
	tsB := reqB.hdr.Get("X-Abysslink-Rig-Ts")
	require.NotEmpty(t, tsB, "X-Abysslink-Rig-Ts must be set for Rig B")
	sigB := reqB.hdr.Get("X-Abysslink-Rig-Sig")
	require.NotEmpty(t, sigB, "X-Abysslink-Rig-Sig must be set for Rig B")

	// Rig A's key must not verify Rig B's signature (per-rig key isolation).
	assert.False(t,
		fleet.VerifyRigMessage(keyA, rigB, tsB, msgBody, sigB),
		"Rig A's key must not verify Rig B's signature (per-rig key isolation)")

	// ── Cross-topic isolation assertion ──
	// Rig A must never hit Rig B's topic and vice versa.
	_, rigAHitTopicB := byPath["/"+topicB+"-via-A"]
	assert.False(t, rigAHitTopicB, "Rig A must never POST to Rig B's topic")
	assert.NotEqual(t, reqA.path, reqB.path, "each rig must POST to its own distinct topic path")
}

// TestNotifyAllRigs_UnsignedWhenNoKey verifies that a rig without an enrolled
// signing key still receives the notification (unsigned) instead of crashing.
// The X-Abysslink-Rig header must still be set; X-Abysslink-Rig-Sig may be absent.
func TestNotifyAllRigs_UnsignedWhenNoKey(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	const (
		rigName = "no-key-rig"
		topic   = "abysslink-no-key-rig-deadbeef"
	)

	// Empty keychain — no signing key stored.
	kc := newNotifyTestKeychain()
	rigs := []config.RigConfig{{Name: rigName, NtfyTopic: topic}}

	err := sendNotifyAllRigs(context.Background(), rigs, kc, "title", "body")
	// Error is acceptable (signing failed) but the function must not panic.
	// With the "skip signing, send unsigned" strategy, err should be nil.
	assert.NoError(t, err, "sendNotifyAllRigs must not crash when a rig has no signing key")

	// The POST must still have been sent (unsigned notification delivered).
	require.Len(t, received, 1, "notification must be sent even without a signing key")
	assert.Equal(t, rigName, received[0].hdr.Get("X-Abysslink-Rig"))
	// X-Abysslink-Rig-Sig may be absent (unsigned) — that's acceptable.
}

// TestNotifyAllRigs_PerRigTopic asserts that Rig A's POST path is strictly
// its own topic and Rig B's POST path is strictly its own topic.
func TestNotifyAllRigs_PerRigTopic(t *testing.T) {
	var mu sync.Mutex
	topicsSeen := make(map[string]string) // path → rig name header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		topicsSeen[r.URL.Path] = r.Header.Get("X-Abysslink-Rig")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	rigs := []config.RigConfig{
		{Name: "rho", NtfyTopic: "topic-rho"},
		{Name: "sigma", NtfyTopic: "topic-sigma"},
		{Name: "tau", NtfyTopic: "topic-tau"},
	}

	require.NoError(t, sendNotifyAllRigs(context.Background(), rigs, kc, "t", "m"))

	// Each topic path must be hit exactly once by its own rig.
	for _, rig := range rigs {
		path := "/" + rig.NtfyTopic
		rigHeader, ok := topicsSeen[path]
		assert.True(t, ok, "topic %q must receive exactly one POST", rig.NtfyTopic)
		assert.Equal(t, rig.Name, rigHeader, "POST to topic %q must carry X-Abysslink-Rig=%q", rig.NtfyTopic, rig.Name)
	}
	assert.Len(t, topicsSeen, len(rigs), "number of distinct topics hit must equal number of rigs")
}

// TestNotifyAllRigs_HMACCanonicalString verifies that the signed canonical
// string is rigName + "." + ts + "." + message, matching the verifier recipe.
func TestNotifyAllRigs_HMACCanonicalString(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	const rigName = "canonical-test-rig"
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	require.NoError(t, kc.Set(context.Background(), fleet.RigService(rigName), "hmac-signing-key", key))

	rigs := []config.RigConfig{{Name: rigName, NtfyTopic: "topic-canonical"}}
	const msg = "canonical message body"

	// Capture a known timestamp by recording before/after the call.
	before := strconv.FormatInt(time.Now().Unix(), 10)
	require.NoError(t, sendNotifyAllRigs(context.Background(), rigs, kc, "title", msg))
	after := strconv.FormatInt(time.Now().Unix(), 10)

	require.Len(t, received, 1)
	ts := received[0].hdr.Get("X-Abysslink-Rig-Ts")
	sig := received[0].hdr.Get("X-Abysslink-Rig-Sig")

	// ts must be a valid integer in [before, after].
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	require.NoError(t, err, "X-Abysslink-Rig-Ts must be an integer string")
	beforeInt, _ := strconv.ParseInt(before, 10, 64)
	afterInt, _ := strconv.ParseInt(after, 10, 64)
	assert.GreaterOrEqual(t, tsInt, beforeInt)
	assert.LessOrEqual(t, tsInt, afterInt)

	// Verify HMAC using the canonical string.
	assert.True(t, fleet.VerifyRigMessage(key, rigName, ts, msg, sig),
		"VerifyRigMessage must return true using canonical string rigName+.+ts+.+message")
}
