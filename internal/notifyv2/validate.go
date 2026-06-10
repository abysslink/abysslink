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

package notifyv2

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	"github.com/abysslink/abysslink/internal/conformance"
)

// Routing-identifier shapes (D-25 + SPEC §4.3). Compiled once at package
// init; validation errors name the allowed charset so callers can self-fix.
var (
	// consumerRe constrains Consumer to a lowercase identifier (D-25) so a
	// hostile value can never carry prose, paths, or payloads downstream.
	consumerRe = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	// sessionRe/windowRe/paneRe pin tmux IDs to their literal forms
	// ($N / @N / %N) so they can never carry argv-injection content (T-27-02).
	sessionRe = regexp.MustCompile(`^\$\d+$`)
	windowRe  = regexp.MustCompile(`^@\d+$`)
	paneRe    = regexp.MustCompile(`^%\d+$`)
	// hostRe pins Host to a hostname shape (alphanumeric start, then
	// alphanumerics/dot/hyphen/underscore, 63 chars max). Host renders
	// verbatim into the ntfy title and body, so without this pin any socket
	// caller could smuggle arbitrary pane content off the device through
	// `host`, defeating the BACK-01 "routing metadata only" invariant.
	// Empty is also valid — the daemon enriches an empty host server-side.
	// Underscore is allowed because os.Hostname is not guaranteed DNS-clean;
	// it cannot carry prose (no spaces, no punctuation beyond . - _).
	hostRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)
)

// tailnetCGNAT is the Tailscale IPv4 CGNAT range and tailnetULA the Tailscale
// IPv6 ULA prefix; a FetchRef URL host must sit inside one of them (or be a
// *.ts.net name) so off-tailnet exfil targets are rejected (T-27-04).
var (
	tailnetCGNAT = netip.MustParsePrefix("100.64.0.0/10")
	tailnetULA   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// maxTitleRunes caps Message.Title on the wire (SPEC §4.3; ntfy renders
// titles single-line and its server-side cap is ~250 — see Pitfall 7).
const maxTitleRunes = 200

// maxDeepLinkBytes caps Message.DeepLink so the link field cannot be abused
// as a content channel (BACK-01: routing metadata only).
const maxDeepLinkBytes = 512

// maxActionLabelRunes caps Action.Label — a button caption, not prose.
const maxActionLabelRunes = 64

// validKinds is the closed kind enum (SPEC §4.2).
var validKinds = map[Kind]bool{
	KindNeedsInput:      true,
	KindCommandDone:     true,
	KindApprovalRequest: true,
	KindWatchFired:      true,
	KindAgentStopped:    true,
}

// validActionIDs is the closed action set: typed and validated now, rendered
// never until Phase 30 wires /approve (D-18).
var validActionIDs = map[string]bool{
	"approve": true,
	"deny":    true,
}

// Validate enforces well-formedness and the secret-free invariant (BACK-01,
// D-17, D-25). Every string field is scanned against
// conformance.SecretPatterns() — there is deliberately no bypass parameter
// and no option to skip the scan.
//
// The secret scan runs FIRST, before any shape check: callers (the daemon)
// log Validate errors and echo them in 422 bodies, so a secret-bearing field
// must be rejected with a generic error before any later check could name or
// echo its value. For the same reason no shape-check error below echoes a raw
// field value — errors name the field and the violated constraint only.
//
// Note: rejection of unknown JSON keys that look like body/content fields
// happens at decode time via json.Decoder.DisallowUnknownFields in the daemon
// (plan 27-05) — a struct-level Validate cannot see keys the decoder dropped.
func (m *Message) Validate() error {
	if err := m.scanSecrets(); err != nil {
		return err
	}
	if m.V != 2 {
		return fmt.Errorf("notifyv2: field v must be 2, got %d", m.V)
	}
	if _, err := ulid.ParseStrict(m.MsgID); err != nil {
		return fmt.Errorf("notifyv2: msg_id is not a valid ULID: %w", err)
	}
	if !validKinds[m.Kind] {
		return fmt.Errorf("notifyv2: unknown kind (allowed: needs_input, command_done, approval_request, watch_fired, agent_stopped)")
	}
	if m.Title == "" {
		return fmt.Errorf("notifyv2: title must be non-empty")
	}
	if n := utf8.RuneCountInString(m.Title); n > maxTitleRunes {
		return fmt.Errorf("notifyv2: title is %d runes, max %d", n, maxTitleRunes)
	}
	if containsControl(m.Title) {
		return fmt.Errorf("notifyv2: title must not contain control characters (it renders into an HTTP header)")
	}
	if err := m.validateRouting(); err != nil {
		return err
	}
	if err := m.validateLinks(); err != nil {
		return err
	}
	if m.Priority != "" && m.Priority != "high" && m.Priority != "normal" {
		return fmt.Errorf("notifyv2: priority: only \"high\", \"normal\", or empty allowed on the wire (D-14 maps to ntfy numbers at render time)")
	}
	return m.validateActions()
}

// validateActions checks the closed action-ID set (D-18) and pins Label to a
// short, control-free button caption (BACK-01: routing metadata only).
func (m *Message) validateActions() error {
	for i, a := range m.Actions {
		if !validActionIDs[a.ID] {
			return fmt.Errorf("notifyv2: actions[%d].id: only \"approve\" or \"deny\" allowed (D-18)", i)
		}
		if n := utf8.RuneCountInString(a.Label); n > maxActionLabelRunes {
			return fmt.Errorf("notifyv2: actions[%d].label is %d runes, max %d", i, n, maxActionLabelRunes)
		}
		if containsControl(a.Label) {
			return fmt.Errorf("notifyv2: actions[%d].label must not contain control characters", i)
		}
	}
	return nil
}

// containsControl reports whether s contains any Unicode control rune
// (includes CR/LF/TAB). Rendered titles and labels travel as HTTP header
// values; a \r\n that passed Validate would deterministically fail — or on
// non-Go paths inject — at delivery time.
func containsControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

// validateRouting checks the Host, SessionRef, and Consumer identifier
// shapes. An all-empty SessionRef is valid — hook/CLI consumers outside tmux
// carry no session identity (D-26: the backbone is not hostage to tmux).
// Error messages name the field and constraint, never the raw value — the
// daemon echoes Validate errors into its log and 422 bodies.
func (m *Message) validateRouting() error {
	if m.Host != "" && !hostRe.MatchString(m.Host) {
		return fmt.Errorf("notifyv2: host must be empty (daemon enriches server-side) or a hostname shape (alphanumeric start, then [a-zA-Z0-9._-], max 63 chars)")
	}
	if m.Session.Session != "" && !sessionRe.MatchString(m.Session.Session) {
		return fmt.Errorf("notifyv2: session id must match ^\\$\\d+$ (tmux $N form)")
	}
	if m.Session.Window != "" && !windowRe.MatchString(m.Session.Window) {
		return fmt.Errorf("notifyv2: window id must match ^@\\d+$ (tmux @N form)")
	}
	if m.Session.Pane != "" && !paneRe.MatchString(m.Session.Pane) {
		return fmt.Errorf("notifyv2: pane id must match ^%%\\d+$ (tmux %%N form)")
	}
	if m.Consumer != "" && !consumerRe.MatchString(m.Consumer) {
		return fmt.Errorf("notifyv2: consumer: only [a-z0-9_-] (max 32 chars) allowed (D-25)")
	}
	return nil
}

// validateLinks checks DeepLink and FetchRef. DeepLink is locked to the
// abysslink:// scheme, length-capped, and control-free (BACK-01); a fetch URL
// must be https on the tailnet CGNAT range, the Tailscale IPv6 ULA prefix, or
// a *.ts.net name with a positive TTL (T-27-04). Error messages never echo
// the raw URL — *url.Error embeds the full input, so parse failures are
// reported generically (the daemon echoes Validate errors into logs).
func (m *Message) validateLinks() error {
	if m.DeepLink != "" {
		if len(m.DeepLink) > maxDeepLinkBytes {
			return fmt.Errorf("notifyv2: deep_link is %d bytes, max %d", len(m.DeepLink), maxDeepLinkBytes)
		}
		if containsControl(m.DeepLink) {
			return fmt.Errorf("notifyv2: deep_link must not contain control characters")
		}
		u, err := url.Parse(m.DeepLink)
		if err != nil {
			return fmt.Errorf("notifyv2: deep_link is not a parseable URL")
		}
		if u.Scheme != "abysslink" {
			return fmt.Errorf("notifyv2: deep_link scheme must be \"abysslink\"")
		}
	}
	if m.Fetch == nil {
		return nil
	}
	u, err := url.Parse(m.Fetch.URLTailnet)
	if err != nil {
		return fmt.Errorf("notifyv2: fetch url_tailnet is not a parseable URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("notifyv2: fetch url_tailnet scheme must be https")
	}
	host := u.Hostname()
	if addr, aerr := netip.ParseAddr(host); aerr == nil {
		if !tailnetCGNAT.Contains(addr) && !tailnetULA.Contains(addr) {
			return fmt.Errorf("notifyv2: fetch url_tailnet host is outside the tailnet ranges (%s, %s)", tailnetCGNAT, tailnetULA)
		}
	} else if !strings.HasSuffix(host, ".ts.net") {
		return fmt.Errorf("notifyv2: fetch url_tailnet host is neither a tailnet IP nor a *.ts.net name")
	}
	if m.Fetch.TTLSeconds <= 0 {
		return fmt.Errorf("notifyv2: fetch ttl_s must be > 0, got %d", m.Fetch.TTLSeconds)
	}
	return nil
}

// scanSecrets scans EVERY string field against the shared conformance secret
// patterns (D-17: no bypass path; SPEC §4.3: single source of truth). It runs
// before all shape checks (see Validate) and returns a descriptive error on
// the first hit, naming the field and the pattern — never echoing the value
// back, which would re-leak it into caller logs.
func (m *Message) scanSecrets() error {
	fields := []struct {
		name  string
		value string
	}{
		{"msg_id", m.MsgID},
		{"host", m.Host},
		{"consumer", m.Consumer},
		{"title", m.Title},
		{"deep_link", m.DeepLink},
		{"session.session", m.Session.Session},
		{"session.window", m.Session.Window},
		{"session.pane", m.Session.Pane},
	}
	if m.Fetch != nil {
		fields = append(fields, struct{ name, value string }{"fetch.url_tailnet", m.Fetch.URLTailnet})
	}
	for i, a := range m.Actions {
		fields = append(fields,
			struct{ name, value string }{fmt.Sprintf("actions[%d].id", i), a.ID},
			struct{ name, value string }{fmt.Sprintf("actions[%d].label", i), a.Label},
		)
	}

	for _, f := range fields {
		if f.value == "" {
			continue
		}
		for _, pat := range conformance.SecretPatterns() {
			if pat.MatchString(f.value) {
				return fmt.Errorf("notifyv2: field %s looks like it carries a secret (matched %s) — refusing (D-17)", f.name, pat.String())
			}
		}
	}
	return nil
}
