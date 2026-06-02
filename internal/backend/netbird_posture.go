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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// nbPostureCheck is a single posture check from GET /api/posture-checks.
// Only the fields needed for CLI display are modelled; the full "checks" object
// is intentionally omitted (the list command shows id/name/description only).
type nbPostureCheck struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// nbCreatePostureCheckRequest is the POST /api/posture-checks request body.
// Checks is a json.RawMessage so the operator-supplied --checks value is passed
// through verbatim; the NetBird API validates the structure server-side
// (T-21-04-03: no shell interpolation, discrete argv).
type nbCreatePostureCheckRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Checks      json.RawMessage `json:"checks,omitempty"`
}

// ListPostureChecks returns all posture checks via GET /api/posture-checks.
// All requests flow through the adapter's doRequest, which carries the
// Authorization: Token header — no new HTTP client (D-05).
func (a *netbirdAdapter) ListPostureChecks(ctx context.Context) ([]nbPostureCheck, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/posture-checks", nil)
	if err != nil {
		return nil, fmt.Errorf("netbird: list posture checks: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netbird: list posture checks: HTTP %d", resp.StatusCode)
	}
	var checks []nbPostureCheck
	if err := json.NewDecoder(resp.Body).Decode(&checks); err != nil {
		return nil, fmt.Errorf("netbird: list posture checks: decode: %w", err)
	}
	return checks, nil
}

// CreatePostureCheck creates a posture check via POST /api/posture-checks.
// Expects HTTP 201 Created and returns the created check.
func (a *netbirdAdapter) CreatePostureCheck(ctx context.Context, req nbCreatePostureCheckRequest) (nbPostureCheck, error) {
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/posture-checks", req)
	if err != nil {
		return nbPostureCheck{}, fmt.Errorf("netbird: create posture check: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusCreated {
		return nbPostureCheck{}, fmt.Errorf("netbird: create posture check: HTTP %d", resp.StatusCode)
	}
	var created nbPostureCheck
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nbPostureCheck{}, fmt.Errorf("netbird: create posture check: decode: %w", err)
	}
	return created, nil
}

// DeletePostureCheck removes a posture check via DELETE /api/posture-checks/{id}.
// Expects HTTP 204 No Content; no body decode is performed.
func (a *netbirdAdapter) DeletePostureCheck(ctx context.Context, id string) error {
	resp, err := a.doRequest(ctx, http.MethodDelete, "/api/posture-checks/"+id, nil)
	if err != nil {
		return fmt.Errorf("netbird: delete posture check %s: %w", id, err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("netbird: delete posture check %s: HTTP %d", id, resp.StatusCode)
	}
	return nil
}
