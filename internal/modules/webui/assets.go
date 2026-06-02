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

package webui

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
)

// embedFS bundles the dashboard's static assets and HTML templates into the
// -tags webui binary so the server needs no external files and serves nothing
// from a CDN (WEB-06). The real htmx.min.js, error-handler.js, style.css, and
// templates land in Plan 03; placeholder files keep the embed directive
// compilable until then.
//
//go:embed assets templates
var embedFS embed.FS

// staticPrefix is the same-origin route under which the embedded JS/CSS assets
// are served. Both htmx.min.js and error-handler.js MUST be served from here so
// the default-src 'self' CSP permits them (WEB-06, Pitfall 7).
const staticPrefix = "/static/"

// ServeStaticAssets registers the embedded assets directory under
// staticPrefix on mux using the Go 1.22 http.FileServerFS.
//
// The embed.FS is rooted at the package directory, so its top-level entries are
// assets/ and templates/. A browser request for /static/style.css must map to
// the embedded assets/style.css. We therefore (a) re-root the FS at the assets
// subtree via fs.Sub so URL paths resolve directly against the real files, and
// (b) strip the full /static/ prefix (not just the leading slash) before the
// lookup. Re-rooting at assets/ also means templates/ is never reachable under
// /static/ (CR-02). It is exported so the route registration is testable in
// isolation.
func ServeStaticAssets(mux *http.ServeMux) {
	assetsFS, err := fs.Sub(embedFS, "assets")
	if err != nil {
		// embedFS is a compile-time constant; "assets" always exists. Fail
		// closed (no handler) and log rather than panic (CLAUDE.md).
		slog.Error("webui: static assets sub-FS unavailable; /static not served", "err", err)
		return
	}
	mux.Handle("GET "+staticPrefix, http.StripPrefix(staticPrefix, http.FileServerFS(assetsFS)))
}
