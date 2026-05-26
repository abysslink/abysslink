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

package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Device represents a device in a Tailscale tailnet.
type Device struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Hostname string   `json:"hostname"`
	Tags     []string `json:"tags"`
}

// oauthTokenResponse is the JSON response from the OAuth token endpoint.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// AdminClient calls the Tailscale admin API using OAuth2 client credentials.
// When clientID and clientSecret are empty, the client operates in manual mode.
type AdminClient struct {
	tailnet      string
	clientID     string
	clientSecret string
	baseURL      string // default "https://api.tailscale.com"; overrideable for tests

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
	httpClient  *http.Client
}

// NewAdminClient returns an AdminClient.
// clientSecret is never placed on argv; it is sent in the request body.
func NewAdminClient(tailnet, clientID, clientSecret string) *AdminClient {
	return &AdminClient{
		tailnet:      tailnet,
		clientID:     clientID,
		clientSecret: clientSecret,
		baseURL:      "https://api.tailscale.com",
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

// NewAdminClientWithBase returns an AdminClient with a custom base URL.
// This is exported to allow tests to point the client at an httptest.Server.
func NewAdminClientWithBase(tailnet, clientID, clientSecret, baseURL string) *AdminClient {
	c := NewAdminClient(tailnet, clientID, clientSecret)
	c.baseURL = baseURL
	return c
}

// isManualMode reports whether the client is in manual mode (no credentials).
func (a *AdminClient) isManualMode() bool {
	return a.clientID == "" || a.clientSecret == ""
}

// ensureToken fetches or refreshes the OAuth token as needed.
func (a *AdminClient) ensureToken(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Now().Before(a.tokenExpiry) {
		return nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", a.clientID)
	form.Set("client_secret", a.clientSecret)

	tokenURL := a.baseURL + "/api/v2/oauth/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("admin: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("admin: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tok oauthTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("admin: parse token response: %w", err)
	}

	a.token = tok.AccessToken
	expiry := tok.ExpiresIn
	if expiry <= 0 {
		expiry = 3600
	}
	// Subtract 30 seconds as buffer to avoid edge-case expiry races.
	a.tokenExpiry = time.Now().Add(time.Duration(expiry-30) * time.Second)
	return nil
}

// doRequest performs an authenticated HTTP request.
func (a *AdminClient) doRequest(ctx context.Context, method, path string, body []byte, headers map[string]string) (*http.Response, error) {
	if err := a.ensureToken(ctx); err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	reqURL := a.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("admin: build request: %w", err)
	}

	a.mu.Lock()
	req.Header.Set("Authorization", "Bearer "+a.token)
	a.mu.Unlock()

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin: request %s %s: %w", method, path, err)
	}
	return resp, nil
}

// Devices returns the list of devices in the tailnet.
func (a *AdminClient) Devices(ctx context.Context) ([]Device, error) {
	if a.isManualMode() {
		return nil, errors.New("manual mode: use 'abysslink acl pull' to manage devices in your browser")
	}

	path := fmt.Sprintf("/api/v2/tailnet/%s/devices", url.PathEscape(a.tailnet))
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("admin: read devices response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin: devices returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Devices []Device `json:"devices"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("admin: parse devices: %w", err)
	}
	return result.Devices, nil
}

// TagDevice sets the tags for a device.
func (a *AdminClient) TagDevice(ctx context.Context, deviceID string, tags []string) error {
	if a.isManualMode() {
		return errors.New("manual mode: use 'abysslink acl pull' to manage tags in your browser")
	}

	payload := struct {
		Tags []string `json:"tags"`
	}{Tags: tags}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("admin: marshal tag payload: %w", err)
	}

	path := fmt.Sprintf("/api/v2/device/%s/tags", url.PathEscape(deviceID))
	resp, err := a.doRequest(ctx, http.MethodPost, path, body, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		rb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin: tag device returned %d: %s", resp.StatusCode, string(rb))
	}
	return nil
}

// CreateAuthKey creates a pre-authorized auth key with the given tags.
func (a *AdminClient) CreateAuthKey(ctx context.Context, tags []string) (string, error) {
	if a.isManualMode() {
		return "", errors.New("manual mode: create auth keys at https://login.tailscale.com/admin/settings/keys")
	}

	payload := struct {
		Capabilities struct {
			Devices struct {
				Create struct {
					Reusable      bool     `json:"reusable"`
					Ephemeral     bool     `json:"ephemeral"`
					Preauthorized bool     `json:"preauthorized"`
					Tags          []string `json:"tags"`
				} `json:"create"`
			} `json:"devices"`
		} `json:"capabilities"`
	}{}
	payload.Capabilities.Devices.Create.Preauthorized = true
	payload.Capabilities.Devices.Create.Tags = tags

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("admin: marshal auth key payload: %w", err)
	}

	path := fmt.Sprintf("/api/v2/tailnet/%s/keys", url.PathEscape(a.tailnet))
	resp, err := a.doRequest(ctx, http.MethodPost, path, body, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("admin: read auth key response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("admin: create auth key returned %d: %s", resp.StatusCode, string(rb))
	}

	var result struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(rb, &result); err != nil {
		return "", fmt.Errorf("admin: parse auth key response: %w", err)
	}
	return result.Key, nil
}

// GetACL returns the current ACL HuJSON and ETag.
func (a *AdminClient) GetACL(ctx context.Context) ([]byte, string, error) {
	if a.isManualMode() {
		return nil, "", errors.New("manual mode: use 'abysslink acl pull' to edit the ACL in your browser")
	}

	path := fmt.Sprintf("/api/v2/tailnet/%s/acl", url.PathEscape(a.tailnet))
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil, map[string]string{
		"Accept": "application/hujson",
	})
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("admin: read ACL response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("admin: get ACL returned %d: %s", resp.StatusCode, string(body))
	}

	etag := resp.Header.Get("ETag")
	return body, etag, nil
}

// SetACL posts a new ACL. Uses ETag for optimistic concurrency.
// Returns an error on 412 Precondition Failed (concurrent modification).
func (a *AdminClient) SetACL(ctx context.Context, acl []byte, etag string) error {
	if a.isManualMode() {
		return fmt.Errorf("manual mode: ACL must be set via https://login.tailscale.com/admin/acls/file")
	}

	headers := map[string]string{
		"Content-Type": "application/hujson",
	}
	if etag != "" {
		headers["If-Match"] = etag
	}

	path := fmt.Sprintf("/api/v2/tailnet/%s/acl", url.PathEscape(a.tailnet))
	resp, err := a.doRequest(ctx, http.MethodPost, path, acl, headers)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusPreconditionFailed {
		return fmt.Errorf("admin: ACL was modified concurrently (412 Precondition Failed); re-fetch and retry")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		rb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin: set ACL returned %d: %s", resp.StatusCode, string(rb))
	}
	return nil
}
