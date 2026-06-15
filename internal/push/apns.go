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

package push

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	apns2 "github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
)

// Compile-time interface guard.
var _ Gateway = (*APNsGateway)(nil)

// apnsBaseURL is a test seam. When non-empty, NewAPNsGateway overrides
// client.Host to this value so tests can point the client at an httptest.Server
// instead of api.push.apple.com.
//
//nolint:gochecknoglobals // test seam — overridden in tests to point at httptest.Server
var apnsBaseURL = ""

// SetAPNsBaseURL overrides the APNs host used by NewAPNsGateway.
// Pass "" to restore the default Production host. Only intended for tests.
func SetAPNsBaseURL(u string) { apnsBaseURL = u }

// SetAPNsHTTPClient replaces the underlying HTTP client of an APNsGateway with
// the supplied client. This allows tests to inject an httptest.Server TLS
// client so the self-signed cert is trusted without any network calls to Apple.
// Only intended for tests.
func SetAPNsHTTPClient(g *APNsGateway, c *http.Client) {
	g.client.HTTPClient = c
}

// APNsGateway sends opaque wake notifications to Apple Push Notification
// service using token-based auth (.p8 key). The push type is always
// PushTypeAlert with priority 10 — background push (PushTypeBackground) is
// structurally absent (D-14). The APNs leg is disabled-by-default at runtime
// and ships interface-complete and experimental until the v5 mobile app ships a
// receiver (D-14 / Phase 29 plan notes).
//
// The daemon calls api.push.apple.com directly — no third-party relay (D-01).
type APNsGateway struct {
	client   *apns2.Client
	bundleID string
}

// NewAPNsGateway constructs an APNsGateway using token-based auth. It calls
// creds.GetAPNsP8 to load the .p8 key, parses it with token.AuthKeyFromBytes,
// and calls .Production() so the client targets api.push.apple.com directly
// (D-01 — daemon calls Apple directly; no relay component).
//
// If the apnsBaseURL test seam is non-empty, client.Host is overridden after
// construction so httptest.Server can stand in for Apple's endpoint.
func NewAPNsGateway(ctx context.Context, creds CredsSource, bundleID string) (*APNsGateway, error) {
	p8, keyID, teamID, err := creds.GetAPNsP8(ctx)
	if err != nil {
		return nil, fmt.Errorf("apns: load .p8 creds: %w", err)
	}

	authKey, err := token.AuthKeyFromBytes(p8)
	if err != nil {
		return nil, fmt.Errorf("apns: parse .p8 key: %w", err)
	}

	t := &token.Token{
		AuthKey: authKey,
		KeyID:   keyID,
		TeamID:  teamID,
	}

	client := apns2.NewTokenClient(t).Production()

	g := &APNsGateway{
		client:   client,
		bundleID: bundleID,
	}

	// Test seam: override host after Production() so tests can point at
	// httptest.Server without touching real Apple endpoints (D-20).
	if apnsBaseURL != "" {
		g.client.Host = apnsBaseURL
	}

	return g, nil
}

// Send delivers an opaque metadata wake to the APNs-registered device.
// The payload contains only routing metadata via opaqueMetaMap — no body
// content, no pane text, no agent output (opaque-wake invariant, T-29-02-1).
//
// Push type is always PushTypeAlert; priority is always 10 (D-14). The device
// token (w.ProviderToken) is secret-class and must never appear in logs (D-17).
//
// On HTTP 410 from APNs: returns ErrDeadToken — caller must prune the device
// token from the enrollment store and drop queued outbox entries (D-12).
// On HTTP 400 with BadDeviceToken: returns a generic rejection error WITHOUT
// pruning — 400 is a caller bug, not a confirmed unregistration (Pitfall 3,
// T-29-02-4).
func (g *APNsGateway) Send(ctx context.Context, w Wake) error {
	meta := opaqueMetaMap(w.Msg) // only routing metadata — no body content

	p := payload.NewPayload().
		AlertTitle(w.Msg.Title).
		MutableContent(). // SPEC §5.2: NSE can rewrite after tailnet fetch
		Custom("meta", meta)

	n := &apns2.Notification{
		DeviceToken: w.ProviderToken, // secret-class: never log this field (D-17)
		Topic:       g.bundleID,
		CollapseID:  w.CollapseID,
		PushType:    apns2.PushTypeAlert, // never PushTypeBackground (D-14)
		Priority:    apns2.PriorityHigh,  // 10 — always high priority for wakes
		Payload:     p,
	}

	resp, err := g.client.PushWithContext(ctx, n)
	if err != nil {
		return fmt.Errorf("apns: push: %w", err)
	}

	// 410: APNs confirmed the token is permanently unregistered (D-12).
	if resp.StatusCode == 410 {
		return ErrDeadToken
	}

	// Any other non-success: log rejection details but do NOT prune.
	// 400 BadDeviceToken in particular must NOT trigger ErrDeadToken (Pitfall 3,
	// T-29-02-4): 400 means the caller sent an invalid token format, not that
	// the device unregistered.
	if !resp.Sent() {
		return fmt.Errorf("apns: push rejected: %s (status %d)", resp.Reason, resp.StatusCode)
	}

	// Log success with safe metadata only — no device token (D-17).
	slog.Info("push: apns sent", "apns_id", resp.ApnsID, "msg_id", w.Msg.MsgID)
	return nil
}
