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
	"fmt"
	"net/http"
	"strings"
	"time"
)

// backendHTTPTimeout bounds every control-plane REST round trip (Headscale,
// NetBird). Without it, http.DefaultClient (no timeout) lets a hung or
// blackholed control plane stall CLI commands forever (NET-06). Per-request
// context cancellation still applies on top of this ceiling.
const backendHTTPTimeout = 30 * time.Second

// backendHTTPClient is the shared HTTP client for all control-plane REST
// calls in this package (Headscale and NetBird adapters, doctor probes).
//
// TLS: the default transport uses the system TLS root store with full
// verification. InsecureSkipVerify is NEVER set (T-12-02-04 / T-13-02-04).
var backendHTTPClient = &http.Client{Timeout: backendHTTPTimeout}

// validateResourceID rejects obviously-invalid control-plane resource IDs
// (node/peer/policy IDs) before they are interpolated into a request path.
// It is a defence-in-depth complement to url.PathEscape: an empty id, or one
// containing a path separator or path-traversal segment, is never a legitimate
// Headscale/NetBird resource id and is rejected outright. This is the same
// WR-01 pattern applied to posture-check IDs in netbird_posture.go — a crafted
// id like "x/../policies/y" must not be able to retarget a DELETE or PUT.
func validateResourceID(kind, id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%s id is empty", kind)
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("%s id %q contains an illegal path segment", kind, id)
	}
	return nil
}
