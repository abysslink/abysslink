//go:build webui

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

// Package webui hosts the opt-in browser dashboard served by abysslinkd over
// the tailnet. The ENTIRE package is gated behind the `webui` build tag, so the
// base abysslinkd binary (built without `-tags webui`) contains zero Web UI
// bytes and never links the Tailscale SDK (WEB-01, T-19-02).
//
// Security spine (this plan, 19-02):
//
//   - TLS is REQUIRED via tailscale.com/client/local.Client.GetCertificate; the
//     listener never binds plaintext, and a non-Tailscale backend fails closed
//     with a webui-tls FATAL doctor finding before any port is opened (WEB-03).
//   - Every request crosses the WhoIs identity gate. Loopback addresses
//     (127.0.0.1, ::1) and unidentifiable peers receive 403 — there is no
//     trusted-local bypass (WEB-04).
//   - CrossOriginProtection (stdlib net/http, Go 1.26) wraps every route; cross-origin
//     requests (Sec-Fetch-Site: cross-site) are rejected (WEB-05). securityHeadersMiddleware
//     applies CSP (default-src 'self'), HSTS, X-Content-Type-Options, Referer-Policy,
//     and COOP on every response (WEB-06).
//   - Mutations are blocked at two layers: config.ValidateWebUI (schema) and the
//     readOnlyMiddleware (HTTP); only the explicitly-unlocked allow_notify path
//     is reachable, and only behind CrossOriginProtection (WEB-02).
//
// Read-only views, templates, and the htmx asset bundle land in Plan 03; the
// daemon entrypoint wiring and the loud one-time startup security note land in
// Plan 04.
package webui
