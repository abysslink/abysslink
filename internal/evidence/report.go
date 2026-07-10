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

package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
)

// renderReport produces the plain-Markdown human-readable report bundled as
// report.md — written for a non-engineer auditor. It states the chain
// verification outcome first (the headline), then a table of the recorded
// actions within the [since, until] window. It contains NO secrets: the audit
// entries are already secret-free (only op/target/hash/time), which is the
// project's immutable audit invariant.
func renderReport(opts CreateOptions, vr audit.VerifyResult, epoch audit.EpochStatus, entries []audit.Entry) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Abysslink audit evidence — %s\n\n", opts.Hostname)
	fmt.Fprintf(&b, "Generated %s by abysslink %s.\n\n", opts.Now.UTC().Format(time.RFC3339), opts.AbysslinkVersion)

	// Same clean-result rule as the signed manifest (chainVerified): a counter
	// status of "unknown"/"mismatch" is NOT a pass, so report.md's headline can
	// never read VALID for a chain audit.Verify itself flags as unverifiable
	// (PC8-1). Otherwise the human report would contradict the CLI's exit-1
	// treatment of an "unknown" counter.
	verdict := "VALID"
	if !chainVerified(vr) {
		verdict = "NOT VALID"
	}
	b.WriteString("## Chain integrity\n\n")
	fmt.Fprintf(&b, "- **Verdict:** %s\n", verdict)
	fmt.Fprintf(&b, "- HMAC signatures verified: %d\n", vr.SigsVerified)
	fmt.Fprintf(&b, "- Entries not cryptographically verified: %d\n", vr.SigsSkipped)
	fmt.Fprintf(&b, "- Current signing-key epoch: %d\n", epoch.PointerEpoch)
	fmt.Fprintf(&b, "- Truncation counter status: %s\n", counterHuman(vr.CounterStatus))
	if vr.Reason != "" {
		fmt.Fprintf(&b, "- Note: %s\n", vr.Reason)
	}
	b.WriteString("\nThe audit chain is HMAC-signed and hash-linked: any edit, reorder, or\n")
	b.WriteString("deletion of a recorded action breaks verification. This report was produced\n")
	b.WriteString("by the operator's abysslink, which holds the signing key, and is itself\n")
	b.WriteString("ed25519-signed in the bundle manifest.\n\n")

	filtered := filterWindow(entries, opts.Since, opts.Until)
	fmt.Fprintf(&b, "## Recorded actions (%d in window)\n\n", len(filtered))
	if len(filtered) == 0 {
		b.WriteString("_No actions recorded in the selected window._\n")
		return []byte(b.String())
	}
	b.WriteString("| Time (UTC) | Action | Target | Dry-run | Epoch | Signed |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, e := range filtered {
		signed := "yes"
		if e.Sig == "" {
			signed = "no"
		}
		dry := "no"
		if e.DryRun {
			dry = "yes"
		}
		ep := e.KeyEpoch
		if ep == 0 {
			ep = 1
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %s |\n",
			e.Time.UTC().Format(time.RFC3339), mdEscape(e.Op), mdEscape(e.Target), dry, ep, signed)
	}
	return []byte(b.String())
}

// filterWindow keeps entries whose Time is within [since, until]. Empty bounds
// are open. Unparseable bounds are ignored (treated as open) — the manifest
// still records the requested range verbatim.
func filterWindow(entries []audit.Entry, since, until string) []audit.Entry {
	sinceT, sinceOK := parseRFC3339(since)
	untilT, untilOK := parseRFC3339(until)
	if !sinceOK && !untilOK {
		return entries
	}
	out := make([]audit.Entry, 0, len(entries))
	for _, e := range entries {
		t := e.Time.UTC()
		if sinceOK && t.Before(sinceT) {
			continue
		}
		if untilOK && t.After(untilT) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func parseRFC3339(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func counterHuman(status string) string {
	switch status {
	case "verified":
		return "verified (no truncation)"
	case "mismatch":
		return "MISMATCH — possible tail truncation"
	case "unknown":
		return "unknown (counter could not confirm the tail)"
	default:
		return "not recorded"
	}
}

// mdEscape neutralizes the Markdown table cell delimiter and newlines so a
// crafted op/target string cannot break the table or inject rows.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
