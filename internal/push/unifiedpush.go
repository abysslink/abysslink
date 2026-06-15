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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/secrets"
)

// Compile-time interface guard.
var _ Gateway = (*UnifiedPushGateway)(nil)

// upHTTPClient is a package-level test seam. When non-nil, Send uses this
// client instead of the default &http.Client{Timeout: 10s}. Tests inject an
// httptest.Server client here.
//
//nolint:gochecknoglobals // test seam
var upHTTPClient *http.Client

// SetUPHTTPClient overrides the HTTP client used by UnifiedPushGateway.Send.
// Pass nil to restore the default client. Only intended for tests.
func SetUPHTTPClient(c *http.Client) { upHTTPClient = c }

// UnifiedPushGateway sends opaque wake metadata to the enrolled device's
// UnifiedPush endpoint URL (stored as w.ProviderToken) using the per-rig ntfy
// keychain credentials (D-18 — same keychain service/account as the ntfy
// module). The endpoint URL itself is secret-class and must never appear in
// logs or audit entries.
type UnifiedPushGateway struct {
	keychain secrets.KeychainStore // nil is valid for headless / no-auth setups
}

// NewUnifiedPushGateway constructs a gateway. kc may be nil if the ntfy
// endpoint does not require authentication (e.g. a private self-hosted
// instance on the tailnet reachable without creds).
func NewUnifiedPushGateway(kc secrets.KeychainStore) *UnifiedPushGateway {
	return &UnifiedPushGateway{keychain: kc}
}

// opaqueMetaMap returns the JSON-safe metadata map for a Wake delivery.
// It contains only routing metadata — never any body content, pane text, or
// agent output. This is the opaque-wake invariant (D-17, T-29-02-1).
//
// Allowed fields: msg_id, host, session (SessionRef JSON), deep_link,
// fetch_url (Fetch.URLTailnet), fetch_ttl_s (Fetch.TTLSeconds).
func opaqueMetaMap(msg notifyv2.Message) map[string]interface{} {
	m := map[string]interface{}{
		"msg_id": msg.MsgID,
		"host":   msg.Host,
	}

	// Include session only when it carries identity (not the zero value).
	if (msg.Session != notifyv2.SessionRef{}) {
		m["session"] = msg.Session
	}

	if msg.DeepLink != "" {
		m["deep_link"] = msg.DeepLink
	}

	if msg.Fetch != nil {
		m["fetch_url"] = msg.Fetch.URLTailnet
		m["fetch_ttl_s"] = msg.Fetch.TTLSeconds
	}

	return m
}

// Send POSTs an opaque metadata JSON body to the enrolled device's UnifiedPush
// endpoint URL. The endpoint URL is w.ProviderToken — never logged (D-17).
//
// Keychain auth is optional: if the keychain returns a password for
// ("abysslink", "ntfy-password"), Basic auth is attached. If the secret is
// absent (ErrNotFound) or the keychain is nil, the request is sent without
// auth. Any other keychain error is logged as a warning and the request
// continues without auth.
func (g *UnifiedPushGateway) Send(ctx context.Context, w Wake) error {
	// w.ProviderToken is the full UnifiedPush endpoint URL — secret class, never log.
	endpointURL := w.ProviderToken

	meta := opaqueMetaMap(w.Msg)
	body, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("unifiedpush: marshal metadata: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("unifiedpush: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Title", w.Msg.Title)
	req.Header.Set("X-Msg-Id", w.Msg.MsgID)

	// Attach keychain auth when available (D-18 — same creds as ntfy module).
	if g.keychain != nil {
		password, kerr := g.keychain.Get(ctx, "abysslink", "ntfy-password")
		switch {
		case kerr == nil && password != "":
			req.SetBasicAuth("admin", password)
		case kerr != nil && !errors.Is(kerr, secrets.ErrNotFound):
			slog.Warn("push: unifiedpush: keychain read failed; sending without auth", "err", kerr)
		// ErrNotFound and empty password: send without auth — silently degrade.
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if upHTTPClient != nil {
		client = upHTTPClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unifiedpush: POST: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unifiedpush: returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	// Log success metadata only — never the endpoint URL or token (D-17).
	slog.Info("push: unifiedpush sent", "msg_id", w.Msg.MsgID)
	return nil
}
