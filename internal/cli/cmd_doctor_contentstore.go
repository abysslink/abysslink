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

package cli

import (
	"context"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
)

// contentStoreModule groups every content-store doctor finding under one
// heading in the doctor render.
const contentStoreModule = "content-store"

// contentStoreOK builds a SeverityOK content-store finding.
func contentStoreOK(check, msg string) modules.Finding {
	return modules.Finding{Module: contentStoreModule, Check: check, Severity: modules.SeverityOK, Message: msg}
}

// contentStoreWarn builds a SeverityWarning content-store finding. The
// content store being off is a valid operator choice, so this family NEVER
// FATALs — it WARNs to surface a silent misconfiguration (daemon down, certs
// disabled, ACL not opened) that would otherwise let the credential pull fail
// for hours while doctor stays green.
func contentStoreWarn(check, msg string) modules.Finding {
	return modules.Finding{Module: contentStoreModule, Check: check, Severity: modules.SeverityWarning, Message: msg}
}

// contentStoreDoctorFindings reports whether the tailnet content store +
// credential pull is actually serving — the preflight that surfaces the silent
// failure modes (daemon not running, tailnet HTTPS certs disabled, mobile→laptop
// ACL not opening tcp:2587) which otherwise leave the phone with "server stopped
// responding" while `doctor` reads green.
//
// It pings the daemon over its unix socket (the same fetchDaemonStatus seam the
// `status` command uses, so tests inject canned daemon responses) and reads the
// daemon's /status content_store field — which already reflects the daemon-side
// disableContent reason (including the eager cert-probe hint), so a "disabled:"
// reason flows straight through here.
//
// Severity matrix (WARN only, never FATAL):
//   - content_store.enabled=false in config → OK (deliberate opt-out, not a problem).
//   - enabled but daemon unreachable → WARN "content-store-daemon-down".
//   - daemon reachable, status "disabled: …" → WARN "content-store-disabled" echoing the reason.
//   - daemon reachable, status "listening on …" → OK "content-store".
//   - daemon reachable but no/unparseable content_store field (older daemon) → OK
//     "content-store-unknown" (no false WARN against a daemon generation that
//     never emits the field).
func contentStoreDoctorFindings(ctx context.Context, cfg *config.Config) []modules.Finding {
	if cfg == nil || !cfg.ContentStore.Enabled {
		// Opt-out is a valid choice — emit an OK so the row renders honestly,
		// never a WARN.
		return []modules.Finding{contentStoreOK("content-store", "content store is disabled in config (opt-out)")}
	}

	extras, err := fetchDaemonStatus(ctx)
	if err != nil || extras == nil {
		return []modules.Finding{contentStoreWarn("content-store-daemon-down",
			"abysslinkd not reachable — the credential pull and content fetch won't work (start it: abysslink daemon enable --apply)")}
	}

	return []modules.Finding{contentStoreFindingForStatus(contentStoreStatusLabel(extras.ContentStore))}
}

// contentStoreStatusLabel decodes the daemon's content_store field (a JSON
// string) into its bare value. An absent or non-string field yields "" so the
// caller treats an older daemon as "unknown", not as a failure.
func contentStoreStatusLabel(raw []byte) string {
	// contentStoreLabel (cmd_status.go) already decodes a JSON string bare and
	// falls back to raw JSON for any other shape; reuse it so the two renders
	// can never drift.
	return contentStoreLabel(raw)
}

// contentStoreFindingForStatus maps a daemon content_store status string to a
// finding. Extracted so contentStoreDoctorFindings stays well under gocyclo 15.
func contentStoreFindingForStatus(status string) modules.Finding {
	status = strings.TrimSpace(status)
	switch {
	case status == "":
		// Older daemon that does not emit content_store; cannot verify, so do
		// not claim a problem (and do not claim OK on a control we did not see).
		return contentStoreOK("content-store-unknown",
			"daemon reachable but did not report content-store state (older daemon) — cannot verify the credential pull")
	case strings.HasPrefix(status, "disabled:"):
		reason := strings.TrimSpace(strings.TrimPrefix(status, "disabled:"))
		return contentStoreWarn("content-store-disabled",
			"tailnet content store is disabled: "+reason)
	case strings.HasPrefix(status, "listening on "):
		addr := strings.TrimSpace(strings.TrimPrefix(status, "listening on "))
		return contentStoreOK("content-store",
			"tailnet content store + credential pull listening on "+addr)
	default:
		// Unrecognised shape from the daemon — surface it rather than guessing OK.
		return contentStoreWarn("content-store-disabled",
			"tailnet content store state could not be interpreted: "+status)
	}
}
