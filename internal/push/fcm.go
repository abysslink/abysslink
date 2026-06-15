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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

// Compile-time interface guard.
var _ Gateway = (*FCMGateway)(nil)

// fcmScope is the OAuth2 scope required for Firebase Cloud Messaging HTTP v1.
const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

// fcmAPIURL is a test seam. When non-empty, Send targets this base URL instead
// of the real FCM endpoint. Tests inject an httptest.Server URL here.
//
//nolint:gochecknoglobals // test seam — overridden in tests to point at httptest.Server
var fcmAPIURL = "https://fcm.googleapis.com"

// SetFCMAPIURL overrides the FCM base URL used by FCMGateway.Send.
// Pass "" to restore the default. Only intended for tests.
func SetFCMAPIURL(u string) {
	if u == "" {
		fcmAPIURL = "https://fcm.googleapis.com"
	} else {
		fcmAPIURL = u
	}
}

// fcmProjectIDDoc is the minimal struct for extracting project_id from a
// GCP service-account JSON credential. It is used before passing the full
// JSON to google.CredentialsFromJSON so that project_id extraction is
// independent of the oauth2 parse (PLAN §research Q2 resolution).
type fcmProjectIDDoc struct {
	ProjectID string `json:"project_id"`
}

// ExtractFCMProjectID extracts the "project_id" field from a GCP
// service-account JSON byte slice. It returns an error if the field is absent
// or empty. This function is exported for use by TestFCMProjectIDFromJSON.
func ExtractFCMProjectID(credJSON []byte) (string, error) {
	var doc fcmProjectIDDoc
	if err := json.Unmarshal(credJSON, &doc); err != nil {
		return "", fmt.Errorf("fcm: parse credential JSON for project_id: %w", err)
	}
	if doc.ProjectID == "" {
		return "", fmt.Errorf("fcm: credential JSON missing required field 'project_id'")
	}
	return doc.ProjectID, nil
}

// FCMGateway sends opaque wake notifications to Firebase Cloud Messaging
// using raw FCM HTTP v1 API. The gateway uses a google.Credentials-backed
// oauth2.TokenSource for automatic token refresh (x/oauth2, RESEARCH A2).
//
// Only data messages are sent — no notification message (T-29-03-5).
// The device registration token (w.ProviderToken) is secret-class and must
// never appear in logs (D-17 / T-29-03-2).
//
// The FCM leg ships disabled-by-default (D-14); Plan 04 adds the config schema.
type FCMGateway struct {
	projectID string
	client    *http.Client // oauth2.NewClient-wrapped auto-refreshing token source
}

// NewFCMGateway constructs an FCMGateway using a GCP service-account JSON
// credential loaded via creds.GetFCMServiceAccount. The project_id is derived
// from the credential JSON (not from a config field — PLAN §research Q2).
// The oauth2 TokenSource auto-refreshes before the 1-hour token expiry (A2).
func NewFCMGateway(ctx context.Context, creds CredsSource) (*FCMGateway, error) {
	credJSON, _, err := creds.GetFCMServiceAccount(ctx)
	if err != nil {
		return nil, fmt.Errorf("fcm: load service-account creds: %w", err)
	}

	// Extract project_id from the JSON before oauth2 parse (PLAN §research Q2).
	projectID, err := ExtractFCMProjectID(credJSON)
	if err != nil {
		return nil, err
	}

	// google.CredentialsFromJSONWithType validates that the JSON is a
	// service_account credential (not an arbitrary untrusted type) before
	// parsing it. Returns a TokenSource that auto-refreshes (RESEARCH A2).
	// Preferred over the deprecated CredentialsFromJSON/CredentialsFromJSONWithParams
	// per the staticcheck SA1019 migration guide.
	googleCreds, err := google.CredentialsFromJSONWithType(ctx, credJSON,
		google.ServiceAccount, fcmScope)
	if err != nil {
		return nil, fmt.Errorf("fcm: parse service-account credentials: %w", err)
	}

	// oauth2.NewClient wraps the TokenSource: it injects a fresh Bearer token
	// on every request, refreshing automatically before expiry.
	client := oauth2.NewClient(ctx, googleCreds.TokenSource)

	return &FCMGateway{
		projectID: projectID,
		client:    client,
	}, nil
}

// NewFCMGatewayForTest constructs an FCMGateway with a pre-built *http.Client
// that already carries an Authorization header, bypassing the oauth2
// service-account flow for unit tests. Only intended for tests.
func NewFCMGatewayForTest(projectID string, client *http.Client) *FCMGateway {
	return &FCMGateway{projectID: projectID, client: client}
}

// fcmErrBody is the minimal struct for parsing a 404 response body from FCM
// to determine whether the error status is UNREGISTERED (dead token) or
// something else (config error — Pitfall 4, T-29-03-4).
type fcmErrBody struct {
	Error struct {
		Status string `json:"status"`
	} `json:"error"`
}

// fcmDataMap builds the FCM data message map from a Wake. All values are
// strings (FCM data message spec requirement — Pitfall 4 analogue). No
// "body", "content", "text", or "pane" keys appear (opaque-wake invariant,
// T-29-03-1). SessionRef is encoded as a JSON string value.
func fcmDataMap(w Wake) map[string]string {
	m := map[string]string{
		"msg_id":      w.Msg.MsgID,
		"host":        w.Msg.Host,
		"title":       w.Msg.Title,
		"collapse_id": w.CollapseID,
	}

	// SessionRef encoded as a compact JSON string (all values must be strings).
	if (w.Msg.Session != notifyv2.SessionRef{}) {
		sessionBytes, err := json.Marshal(w.Msg.Session)
		if err == nil {
			m["session"] = string(sessionBytes)
		}
	}

	if w.Msg.DeepLink != "" {
		m["deep_link"] = w.Msg.DeepLink
	}

	if w.Msg.Fetch != nil {
		m["fetch_url"] = w.Msg.Fetch.URLTailnet
		m["fetch_ttl"] = strconv.Itoa(w.Msg.Fetch.TTLSeconds)
	}

	return m
}

// Send delivers an opaque metadata data message to the FCM-registered device.
// The payload contains only routing metadata — no body content, no pane text,
// no agent output (opaque-wake invariant, T-29-03-1).
//
// Push message type is always "data" — no "notification" key is ever set
// (T-29-03-5 / D-14).
//
// On HTTP 404 + UNREGISTERED: returns ErrDeadToken — caller must prune
// the device token and drop queued outbox entries (D-12 / T-29-03-4).
// On HTTP 404 + any other status: returns a config-error (NOT ErrDeadToken).
// On any other non-200: returns a generic HTTP error.
//
// The device registration token (w.ProviderToken) is secret-class and must
// never appear in slog output (D-17 / T-29-03-2).
func (f *FCMGateway) Send(ctx context.Context, w Wake) error {
	url := fcmAPIURL + "/v1/projects/" + f.projectID + "/messages:send"

	envelope := map[string]interface{}{
		"message": map[string]interface{}{
			"token": w.ProviderToken, // secret-class: never log this field (D-17)
			"data":  fcmDataMap(w),
			"android": map[string]string{
				"priority": "high", // defeats Android Doze (PLAN §spec)
			},
		},
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("fcm: marshal message envelope: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("fcm: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("fcm: POST: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is non-actionable on read path

	if resp.StatusCode == http.StatusNotFound {
		// Read up to 512 bytes to parse error status — DOS-bounded (PLAN §spec).
		errBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		var errBody fcmErrBody
		if jsonErr := json.Unmarshal(errBytes, &errBody); jsonErr == nil &&
			errBody.Error.Status == "UNREGISTERED" {
			// 404+UNREGISTERED: device token is permanently unregistered (D-12).
			return ErrDeadToken
		}
		// 404+anything else: config error (wrong project_id, SENDER_ID_MISMATCH,
		// etc.) — must NOT trigger dead-token pruning (Pitfall 4, T-29-03-4).
		return fmt.Errorf("fcm: send returned HTTP 404 (non-UNREGISTERED error)")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fcm: send returned HTTP %d", resp.StatusCode)
	}

	// Log success with safe metadata only — no device token (D-17 / T-29-03-2).
	slog.Info("push: fcm sent", "msg_id", w.Msg.MsgID)
	return nil
}
