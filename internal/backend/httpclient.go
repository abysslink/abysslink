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
	"net/http"
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
