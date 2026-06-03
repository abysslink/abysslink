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

// This file pins the Tailscale SDK packages the dashboard depends on so that
// `go mod tidy` retains tailscale.com as a direct module requirement. The
// package-level documentation lives in doc.go. The blank import here is
// belt-and-suspenders: server.go and middleware.go import this package
// directly, but keeping the pin avoids tidy churn should those imports move.
package webui

import (
	// local.Client.GetCertificate supplies the Tailscale TLS cert (WEB-03) and
	// WhoIs identity (WEB-04).
	_ "tailscale.com/client/local"
)
