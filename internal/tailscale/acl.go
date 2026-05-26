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

// aclDoc is the internal representation of a Tailscale ACL document.
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
type ACLEditor struct {
	raw []byte // current document (stored as standard JSON after first parse)
	doc aclDoc
}

// NewACLEditor returns an editor for the given HuJSON bytes.
// Returns error if the bytes are not valid HuJSON.
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

	e := &ACLEditor{doc: doc}
	if err := e.flush(); err != nil {
		return nil, err
	}
	return e, nil
}

// flush re-marshals the doc into e.raw.
func (e *ACLEditor) flush() error {
	b, err := json.MarshalIndent(&e.doc, "", "    ")
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
				IP:  []string{"tcp:22", "udp:60000-61000"},
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

// EnsureGrant ensures the mobile→laptop grant (tcp:22, udp:60000-61000) exists.
// Idempotent: no-op if an equivalent grant already exists.
func (e *ACLEditor) EnsureGrant() error {
	wantSrc := "tag:mobile"
	wantDst := "tag:laptop"
	for _, g := range e.doc.Grants {
		if containsString(g.Src, wantSrc) && containsString(g.Dst, wantDst) {
			return nil // already present
		}
	}
	e.doc.Grants = append(e.doc.Grants, aclGrant{
		Src: []string{wantSrc},
		Dst: []string{wantDst},
		IP:  []string{"tcp:22", "udp:60000-61000"},
	})
	return e.flush()
}

// EnsureSSHRule ensures the SSH check rule for owner→tag:laptop with sshUser exists.
// Idempotent: updates checkPeriod if rule exists but period differs.
func (e *ACLEditor) EnsureSSHRule(owner, sshUser, checkPeriod string) error {
	for i, r := range e.doc.SSH {
		if containsString(r.Src, owner) &&
			containsString(r.Dst, "tag:laptop") &&
			containsString(r.Users, sshUser) {
			// Rule exists; update checkPeriod if needed.
			if r.CheckPeriod != checkPeriod {
				e.doc.SSH[i].CheckPeriod = checkPeriod
				return e.flush()
			}
			return nil // fully idempotent
		}
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

// Diff returns a unified diff string between old and new HuJSON/JSON bytes.
// It uses a simple line-by-line diff — suitable for audit logging.
func Diff(oldBytes, newBytes []byte) string {
	oldLines := strings.Split(string(oldBytes), "\n")
	newLines := strings.Split(string(newBytes), "\n")

	var buf bytes.Buffer
	// Simple output: lines removed (prefix -) and lines added (prefix +).
	oldSet := make(map[string]bool, len(oldLines))
	for _, l := range oldLines {
		oldSet[l] = true
	}
	newSet := make(map[string]bool, len(newLines))
	for _, l := range newLines {
		newSet[l] = true
	}

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
