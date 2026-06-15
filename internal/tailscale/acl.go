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

package tailscale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

// Managed top-level ACL keys: the only sections the editor modifies. Every
// other top-level key in the user's tailnet policy (acls, groups, hosts,
// tests, autoApprovers, nodeAttrs, derpMap, postures, ...) is preserved
// verbatim across the round-trip — see ACLEditor.extra.
const (
	keyTagOwners = "tagOwners"
	keyGrants    = "grants"
	keySSH       = "ssh"
)

// requiredGrantPorts is the minimal mobile→laptop port set abysslink needs:
// SSH (22), ntfy push (2586), the tailnet content store + first-contact
// credential pull (2587 — the BACK-06/BACK-09 HTTPS listener; without this the
// phone is blocked at the tailnet ACL and the pull/content fetch is
// "not reachable"), and the mosh UDP range. 2587 is config.DefaultContentStorePort;
// a customized content_store.port would need a manual grant (ACL port derivation
// from config is a follow-up — EnsureGrant is a no-arg interface method today).
var requiredGrantPorts = []string{"tcp:22", "tcp:2586", "tcp:2587", "udp:60000-61000"}

// aclDoc is the internal representation of the ACL sections abysslink manages.
type aclDoc struct {
	TagOwners map[string][]string `json:"tagOwners,omitempty"`
	Grants    []aclGrant          `json:"grants,omitempty"`
	SSH       []aclSSHRule        `json:"ssh,omitempty"`
}

type aclGrant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
}

type aclSSHRule struct {
	Action      string   `json:"action"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Users       []string `json:"users"`
	CheckPeriod string   `json:"checkPeriod"`
}

// ACLEditor edits a Tailscale HuJSON ACL document idempotently.
//
// Only the tagOwners, grants, and ssh sections are interpreted; all other
// top-level keys of the policy are carried through unmodified so a push of
// the edited document never deletes the user's acls, groups, hosts, tests,
// autoApprovers, or any other section.
type ACLEditor struct {
	raw []byte // current document (stored as standard JSON after first parse)
	doc aclDoc
	// extra holds every top-level key the editor does not manage, preserved
	// byte-for-byte (modulo re-indentation) across the round-trip.
	extra map[string]json.RawMessage
}

// NewACLEditor returns an editor for the given HuJSON bytes.
// Returns error if the bytes are not valid HuJSON.
//
// Known limitation: the document is standardized to plain JSON, so HuJSON
// comments and trailing commas are NOT preserved in the output. All top-level
// keys and their values are preserved.
func NewACLEditor(raw []byte) (*ACLEditor, error) {
	// Validate and standardize HuJSON to plain JSON.
	std, err := hujson.Standardize(append([]byte(nil), raw...))
	if err != nil {
		return nil, fmt.Errorf("acl: invalid HuJSON: %w", err)
	}

	var doc aclDoc
	if err := json.Unmarshal(std, &doc); err != nil {
		return nil, fmt.Errorf("acl: unmarshal: %w", err)
	}

	// Capture every top-level key we do not manage so flush() can write the
	// full policy back out instead of silently dropping unknown sections.
	var all map[string]json.RawMessage
	if err := json.Unmarshal(std, &all); err != nil {
		return nil, fmt.Errorf("acl: unmarshal top-level keys: %w", err)
	}
	extra := make(map[string]json.RawMessage, len(all))
	for k, v := range all {
		switch k {
		case keyTagOwners, keyGrants, keySSH:
			// managed — re-marshaled from e.doc on flush
		default:
			extra[k] = v
		}
	}

	e := &ACLEditor{doc: doc, extra: extra}
	if err := e.flush(); err != nil {
		return nil, err
	}
	return e, nil
}

// flush re-marshals the doc (managed sections + preserved unmanaged keys)
// into e.raw.
func (e *ACLEditor) flush() error {
	out := make(map[string]json.RawMessage, len(e.extra)+3)
	for k, v := range e.extra {
		out[k] = v
	}
	managed := map[string]any{}
	if len(e.doc.TagOwners) > 0 {
		managed[keyTagOwners] = e.doc.TagOwners
	}
	if len(e.doc.Grants) > 0 {
		managed[keyGrants] = e.doc.Grants
	}
	if len(e.doc.SSH) > 0 {
		managed[keySSH] = e.doc.SSH
	}
	for k, v := range managed {
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("acl: marshal %s: %w", k, err)
		}
		out[k] = b
	}

	b, err := json.MarshalIndent(out, "", "    ")
	if err != nil {
		return fmt.Errorf("acl: marshal: %w", err)
	}
	e.raw = b
	return nil
}

// DefaultACL returns the minimal safe ACL for abysslink.
// owner is the tagOwners email; sshUser is the macOS/Linux username.
func DefaultACL(owner, sshUser string) []byte {
	doc := aclDoc{
		TagOwners: map[string][]string{
			"tag:mobile": {owner},
			"tag:laptop": {owner},
		},
		Grants: []aclGrant{
			{
				Src: []string{"tag:mobile"},
				Dst: []string{"tag:laptop"},
				IP:  append([]string(nil), requiredGrantPorts...),
			},
		},
		SSH: []aclSSHRule{
			{
				Action:      "check",
				Src:         []string{owner},
				Dst:         []string{"tag:laptop"},
				Users:       []string{sshUser},
				CheckPeriod: "12h",
			},
		},
	}
	b, _ := json.MarshalIndent(&doc, "", "    ")
	return b
}

// EnsureTagOwners ensures tag:mobile and tag:laptop both list owner.
// Idempotent: no-op if already present.
func (e *ACLEditor) EnsureTagOwners(owner string) error {
	if e.doc.TagOwners == nil {
		e.doc.TagOwners = make(map[string][]string)
	}
	for _, tag := range []string{"tag:mobile", "tag:laptop"} {
		if !containsString(e.doc.TagOwners[tag], owner) {
			e.doc.TagOwners[tag] = append(e.doc.TagOwners[tag], owner)
		}
	}
	return e.flush()
}

// EnsureGrant ensures the mobile→laptop grant covers all required ports
// (tcp:22, tcp:2586, tcp:2587, udp:60000-61000).
//
// Idempotent: no-op when the union of all existing mobile→laptop grants
// already covers the required ports (or one grants "*"). When a matching
// grant exists but ports are missing, the first matching grant is extended
// with the missing ports rather than appending a duplicate grant.
func (e *ACLEditor) EnsureGrant() error {
	const wantSrc, wantDst = "tag:mobile", "tag:laptop"

	firstMatch := -1
	covered := make(map[string]bool)
	for i, g := range e.doc.Grants {
		if !containsString(g.Src, wantSrc) || !containsString(g.Dst, wantDst) {
			continue
		}
		if firstMatch < 0 {
			firstMatch = i
		}
		for _, p := range g.IP {
			covered[p] = true
		}
	}

	if firstMatch >= 0 {
		if covered["*"] {
			return nil // wildcard grant covers every required port
		}
		var missing []string
		for _, p := range requiredGrantPorts {
			if !covered[p] {
				missing = append(missing, p)
			}
		}
		if len(missing) == 0 {
			return nil // already covered
		}
		e.doc.Grants[firstMatch].IP = append(e.doc.Grants[firstMatch].IP, missing...)
		return e.flush()
	}

	e.doc.Grants = append(e.doc.Grants, aclGrant{
		Src: []string{wantSrc},
		Dst: []string{wantDst},
		IP:  append([]string(nil), requiredGrantPorts...),
	})
	return e.flush()
}

// EnsureSSHRule ensures the SSH *check* rule for owner→tag:laptop with sshUser
// exists. Idempotent: updates checkPeriod if the rule exists but the period
// differs, and rewrites a weaker action (e.g. "accept", which skips re-auth
// entirely) to "check" — the 12h re-auth interval is an immutable security
// default and an accept rule must never satisfy the check requirement.
func (e *ACLEditor) EnsureSSHRule(owner, sshUser, checkPeriod string) error {
	for i := range e.doc.SSH {
		r := &e.doc.SSH[i]
		if !containsString(r.Src, owner) ||
			!containsString(r.Dst, "tag:laptop") ||
			!containsString(r.Users, sshUser) {
			continue
		}
		// Rule exists; converge action and checkPeriod if needed.
		changed := false
		if r.Action != "check" {
			r.Action = "check"
			changed = true
		}
		if r.CheckPeriod != checkPeriod {
			r.CheckPeriod = checkPeriod
			changed = true
		}
		if !changed {
			return nil // fully idempotent
		}
		return e.flush()
	}
	// Rule not found; add it.
	e.doc.SSH = append(e.doc.SSH, aclSSHRule{
		Action:      "check",
		Src:         []string{owner},
		Dst:         []string{"tag:laptop"},
		Users:       []string{sshUser},
		CheckPeriod: checkPeriod,
	})
	return e.flush()
}

// Bytes returns the current JSON document.
func (e *ACLEditor) Bytes() []byte {
	return e.raw
}

// Diff returns an ordered line diff between old and new HuJSON/JSON bytes:
// removed lines prefixed "- " and added lines prefixed "+ ", emitted in
// document order (LCS-based, so duplicated and reordered lines are visible).
// No context lines are printed — suitable for audit logging, not `patch`.
func Diff(oldBytes, newBytes []byte) string {
	oldLines := strings.Split(string(oldBytes), "\n")
	newLines := strings.Split(string(newBytes), "\n")
	n, m := len(oldLines), len(newLines)

	// Guard the quadratic LCS table against pathological inputs (~32 MB cap).
	const maxCells = 4 << 20
	if n*m > maxCells {
		return setDiff(oldLines, newLines)
	}

	// dp[i][j] = length of the LCS of oldLines[i:] and newLines[j:].
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var buf bytes.Buffer
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && oldLines[i] == newLines[j]:
			i++
			j++
		case i < n && (j == m || dp[i+1][j] >= dp[i][j+1]):
			fmt.Fprintf(&buf, "- %s\n", oldLines[i])
			i++
		default:
			fmt.Fprintf(&buf, "+ %s\n", newLines[j])
			j++
		}
	}
	return buf.String()
}

// setDiff is the size-bounded fallback for Diff: set-membership comparison.
// Duplicate-count changes and reorderings are invisible here; it is only used
// when the inputs are too large for the LCS table.
func setDiff(oldLines, newLines []string) string {
	oldSet := make(map[string]bool, len(oldLines))
	for _, l := range oldLines {
		oldSet[l] = true
	}
	newSet := make(map[string]bool, len(newLines))
	for _, l := range newLines {
		newSet[l] = true
	}

	var buf bytes.Buffer
	for _, l := range oldLines {
		if !newSet[l] {
			fmt.Fprintf(&buf, "- %s\n", l)
		}
	}
	for _, l := range newLines {
		if !oldSet[l] {
			fmt.Fprintf(&buf, "+ %s\n", l)
		}
	}
	return buf.String()
}

// containsString reports whether haystack contains needle.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
