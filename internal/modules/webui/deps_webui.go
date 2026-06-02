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

//go:build webui

// Package webui hosts the opt-in browser dashboard served by abysslinkd over
// the tailnet. The entire package is gated behind the `webui` build tag, so the
// base abysslinkd binary (built without `-tags webui`) contains zero Web UI
// bytes and never links the Tailscale SDK (WEB-01, T-19-02).
//
// This file pins the Tailscale SDK packages the dashboard depends on so that
// `go mod tidy` retains tailscale.com as a direct module requirement before the
// real handlers (Plan 04) import them. It is intentionally minimal — the
// listener, TLS, WhoIs auth, CSRF, and read-only middleware land in later plans.
package webui

import (
	// local.Client.GetCertificate supplies the Tailscale TLS cert (WEB-03) and
	// WhoIs identity (WEB-04).
	_ "tailscale.com/client/local"
	// safeweb provides the CSRF-protected mux for the dashboard (WEB-05).
	_ "tailscale.com/safeweb"
)
