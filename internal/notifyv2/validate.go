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
)

// tailnetCGNAT is the Tailscale CGNAT range; a FetchRef URL host must sit
// inside it (or be a *.ts.net name) so off-tailnet exfil targets are rejected
// (T-27-04).
var tailnetCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// maxTitleRunes caps Message.Title on the wire (SPEC §4.3; ntfy renders
// titles single-line and its server-side cap is ~250 — see Pitfall 7).
const maxTitleRunes = 200

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
// Note: rejection of unknown JSON keys that look like body/content fields
// happens at decode time via json.Decoder.DisallowUnknownFields in the daemon
// (plan 27-05) — a struct-level Validate cannot see keys the decoder dropped.
func (m *Message) Validate() error {
	if m.V != 2 {
		return fmt.Errorf("notifyv2: field v must be 2, got %d", m.V)
	}
	if _, err := ulid.ParseStrict(m.MsgID); err != nil {
		return fmt.Errorf("notifyv2: msg_id %q is not a valid ULID: %w", m.MsgID, err)
	}
	if !validKinds[m.Kind] {
		return fmt.Errorf("notifyv2: unknown kind %q (allowed: needs_input, command_done, approval_request, watch_fired, agent_stopped)", m.Kind)
	}
	if m.Title == "" {
		return fmt.Errorf("notifyv2: title must be non-empty")
	}
	if n := utf8.RuneCountInString(m.Title); n > maxTitleRunes {
		return fmt.Errorf("notifyv2: title is %d runes, max %d", n, maxTitleRunes)
	}
	if err := m.validateRouting(); err != nil {
		return err
	}
	if err := m.validateLinks(); err != nil {
		return err
	}
	if m.Priority != "" && m.Priority != "high" && m.Priority != "normal" {
		return fmt.Errorf("notifyv2: priority %q: only \"high\", \"normal\", or empty allowed on the wire (D-14 maps to ntfy numbers at render time)", m.Priority)
	}
	for _, a := range m.Actions {
		if !validActionIDs[a.ID] {
			return fmt.Errorf("notifyv2: action id %q: only \"approve\" or \"deny\" allowed (D-18)", a.ID)
		}
	}
	return m.scanSecrets()
}

// validateRouting checks the SessionRef and Consumer identifier shapes. An
// all-empty SessionRef is valid — hook/CLI consumers outside tmux carry no
// session identity (D-26: the backbone is not hostage to tmux).
func (m *Message) validateRouting() error {
	if m.Session.Session != "" && !sessionRe.MatchString(m.Session.Session) {
		return fmt.Errorf("notifyv2: session id %q: must match ^\\$\\d+$ (tmux $N form)", m.Session.Session)
	}
	if m.Session.Window != "" && !windowRe.MatchString(m.Session.Window) {
		return fmt.Errorf("notifyv2: window id %q: must match ^@\\d+$ (tmux @N form)", m.Session.Window)
	}
	if m.Session.Pane != "" && !paneRe.MatchString(m.Session.Pane) {
		return fmt.Errorf("notifyv2: pane id %q: must match ^%%\\d+$ (tmux %%N form)", m.Session.Pane)
	}
	if m.Consumer != "" && !consumerRe.MatchString(m.Consumer) {
		return fmt.Errorf("notifyv2: consumer %q: only [a-z0-9_-] (max 32 chars) allowed (D-25)", m.Consumer)
	}
	return nil
}

// validateLinks checks DeepLink and FetchRef. DeepLink is locked to the
// abysslink:// scheme; a fetch URL must be https on the tailnet CGNAT range
// or a *.ts.net name with a positive TTL (T-27-04).
func (m *Message) validateLinks() error {
	if m.DeepLink != "" {
		u, err := url.Parse(m.DeepLink)
		if err != nil {
			return fmt.Errorf("notifyv2: deep_link %q: %w", m.DeepLink, err)
		}
		if u.Scheme != "abysslink" {
			return fmt.Errorf("notifyv2: deep_link scheme must be \"abysslink\", got %q", u.Scheme)
		}
	}
	if m.Fetch == nil {
		return nil
	}
	u, err := url.Parse(m.Fetch.URLTailnet)
	if err != nil {
		return fmt.Errorf("notifyv2: fetch url_tailnet %q: %w", m.Fetch.URLTailnet, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("notifyv2: fetch url_tailnet scheme must be https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if addr, aerr := netip.ParseAddr(host); aerr == nil {
		if !tailnetCGNAT.Contains(addr) {
			return fmt.Errorf("notifyv2: fetch url_tailnet host %s is outside the tailnet range %s", host, tailnetCGNAT)
		}
	} else if !strings.HasSuffix(host, ".ts.net") {
		return fmt.Errorf("notifyv2: fetch url_tailnet host %q is neither a tailnet IP nor a *.ts.net name", host)
	}
	if m.Fetch.TTLSeconds <= 0 {
		return fmt.Errorf("notifyv2: fetch ttl_s must be > 0, got %d", m.Fetch.TTLSeconds)
	}
	return nil
}

// scanSecrets scans EVERY string field against the shared conformance secret
// patterns (D-17: no bypass path; SPEC §4.3: single source of truth). It
// returns a descriptive error on the first hit, naming the field and the
// pattern — never echoing the full value back, which would re-leak it into
// caller logs.
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
