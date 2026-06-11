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

package tailscale_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/tailscale"
)

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // testdata path is fixed prefix
	require.NoError(t, err, "reading golden file %s", name)
	return b
}

func TestDefaultACL(t *testing.T) {
	got := tailscale.DefaultACL("owner@example.com", "macuser")
	golden := readGolden(t, "acl_default.json")
	assert.JSONEq(t, string(golden), string(got))
}

func TestEnsureTagOwners_New(t *testing.T) {
	// Start from an empty document.
	e, err := tailscale.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureTagOwners("owner@example.com"))

	golden := readGolden(t, "acl_with_tag_owners.json")
	assert.JSONEq(t, string(golden), string(e.Bytes()))
}

func TestEnsureTagOwners_Idempotent(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureTagOwners("owner@example.com"))
	first := string(e.Bytes())

	require.NoError(t, e.EnsureTagOwners("owner@example.com"))
	second := string(e.Bytes())

	assert.JSONEq(t, first, second, "second call should be idempotent")
}

func TestEnsureGrant_New(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureGrant())

	golden := readGolden(t, "acl_with_grant.json")
	assert.JSONEq(t, string(golden), string(e.Bytes()))
}

func TestEnsureGrant_Idempotent(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureGrant())
	first := string(e.Bytes())

	require.NoError(t, e.EnsureGrant())
	second := string(e.Bytes())

	assert.JSONEq(t, first, second, "second call should be idempotent")
}

func TestEnsureSSHRule_New(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))

	golden := readGolden(t, "acl_with_ssh.json")
	assert.JSONEq(t, string(golden), string(e.Bytes()))
}

func TestEnsureSSHRule_Idempotent(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))
	first := string(e.Bytes())

	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))
	second := string(e.Bytes())

	assert.JSONEq(t, first, second, "second call should be idempotent")
}

func TestEnsureSSHRule_UpdatesCheckPeriod(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))
	// Now update the checkPeriod.
	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "6h"))

	// Should still have exactly one SSH rule.
	var result struct {
		SSH []struct {
			CheckPeriod string `json:"checkPeriod"`
		} `json:"ssh"`
	}
	require.NoError(t, json.Unmarshal(e.Bytes(), &result))
	require.Len(t, result.SSH, 1)
	assert.Equal(t, "6h", result.SSH[0].CheckPeriod)
}

func TestNewACLEditor_InvalidHuJSON(t *testing.T) {
	_, err := tailscale.NewACLEditor([]byte(`{not valid json`))
	require.Error(t, err)
}

func TestNewACLEditor_ValidHuJSON(t *testing.T) {
	// HuJSON with trailing commas and comments.
	huJSON := []byte(`{
		"tagOwners": {
			"tag:mobile": ["user@example.com"]
		}
	}`)
	e, err := tailscale.NewACLEditor(huJSON)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

// fullPolicy is a realistic tailnet policy carrying every common unmanaged
// section plus HuJSON comments and trailing commas. The ACL editor must never
// drop any of these keys on the round-trip — `acl push --apply` previously
// deleted them from the live tailnet (CRITICAL data-loss bug).
const fullPolicy = `{
	// Tailnet policy with comments and trailing commas (HuJSON).
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
	"groups": {
		"group:eng": ["a@example.com", "b@example.com"],
	},
	"hosts": {
		"webserver": "100.64.0.10",
	},
	"tests": [
		{"src": "a@example.com", "accept": ["webserver:443"]},
	],
	"autoApprovers": {
		"routes": {"10.0.0.0/24": ["tag:router"]},
	},
	"nodeAttrs": [
		{"target": ["*"], "attr": ["mullvad"]},
	],
	"randomizeClientPorts": true,
	"tagOwners": {
		"tag:existing": ["c@example.com"],
	},
}`

// unmanagedSections maps each unmanaged top-level key of fullPolicy to its
// expected (semantically equivalent) JSON value after the round-trip.
var unmanagedSections = map[string]string{
	"acls":                 `[{"action": "accept", "src": ["*"], "dst": ["*:*"]}]`,
	"groups":               `{"group:eng": ["a@example.com", "b@example.com"]}`,
	"hosts":                `{"webserver": "100.64.0.10"}`,
	"tests":                `[{"src": "a@example.com", "accept": ["webserver:443"]}]`,
	"autoApprovers":        `{"routes": {"10.0.0.0/24": ["tag:router"]}}`,
	"nodeAttrs":            `[{"target": ["*"], "attr": ["mullvad"]}]`,
	"randomizeClientPorts": `true`,
}

func assertUnmanagedPreserved(t *testing.T, doc []byte) {
	t.Helper()
	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &got))
	for key, want := range unmanagedSections {
		require.Contains(t, got, key, "unmanaged top-level key %q must survive the round-trip", key)
		assert.JSONEq(t, want, string(got[key]), "unmanaged key %q must be value-preserved", key)
	}
}

func TestNewACLEditor_RoundTripPreservesUnmanagedKeys(t *testing.T) {
	// No edits at all: parse → Bytes must keep every unmanaged section.
	// Note: HuJSON comments are NOT preserved (the editor standardizes to
	// plain JSON) — that limitation is documented on NewACLEditor.
	e, err := tailscale.NewACLEditor([]byte(fullPolicy))
	require.NoError(t, err)
	assertUnmanagedPreserved(t, e.Bytes())
}

func TestACLEditor_EditsPreserveUnmanagedKeys(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(fullPolicy))
	require.NoError(t, err)

	require.NoError(t, e.EnsureTagOwners("owner@example.com"))
	require.NoError(t, e.EnsureGrant())
	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))

	out := e.Bytes()
	assertUnmanagedPreserved(t, out)

	// The pre-existing managed content must also survive alongside the edits.
	var got struct {
		TagOwners map[string][]string `json:"tagOwners"`
	}
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, []string{"c@example.com"}, got.TagOwners["tag:existing"],
		"pre-existing tagOwners entries must be preserved")
	assert.Equal(t, []string{"owner@example.com"}, got.TagOwners["tag:mobile"])
	assert.Equal(t, []string{"owner@example.com"}, got.TagOwners["tag:laptop"])

	// Edits must remain idempotent with unmanaged keys present, so the
	// "already converged" before/after comparison in applyAdmin holds.
	first := append([]byte(nil), e.Bytes()...)
	require.NoError(t, e.EnsureTagOwners("owner@example.com"))
	require.NoError(t, e.EnsureGrant())
	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))
	assert.Equal(t, string(first), string(e.Bytes()), "re-applying must be byte-identical")
}

func TestEnsureGrant_ExtendsGrantMissingRequiredPorts(t *testing.T) {
	// An existing mobile→laptop grant that lacks the abysslink ports must be
	// extended, not treated as satisfying the requirement (connectivity would
	// silently be broken while validate reported converged).
	e, err := tailscale.NewACLEditor([]byte(
		`{"grants":[{"src":["tag:mobile"],"dst":["tag:laptop"],"ip":["tcp:443"]}]}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureGrant())

	var got struct {
		Grants []struct {
			IP []string `json:"ip"`
		} `json:"grants"`
	}
	require.NoError(t, json.Unmarshal(e.Bytes(), &got))
	require.Len(t, got.Grants, 1, "must extend the existing grant, not append a second one")
	assert.Contains(t, got.Grants[0].IP, "tcp:443", "pre-existing ports must be kept")
	assert.Contains(t, got.Grants[0].IP, "tcp:22")
	assert.Contains(t, got.Grants[0].IP, "tcp:2586")
	assert.Contains(t, got.Grants[0].IP, "udp:60000-61000")
}

func TestEnsureGrant_ExtendsGrantWithPartialPorts(t *testing.T) {
	e, err := tailscale.NewACLEditor([]byte(
		`{"grants":[{"src":["tag:mobile"],"dst":["tag:laptop"],"ip":["tcp:22"]}]}`))
	require.NoError(t, err)

	require.NoError(t, e.EnsureGrant())

	var got struct {
		Grants []struct {
			IP []string `json:"ip"`
		} `json:"grants"`
	}
	require.NoError(t, json.Unmarshal(e.Bytes(), &got))
	require.Len(t, got.Grants, 1)
	assert.ElementsMatch(t, []string{"tcp:22", "tcp:2586", "udp:60000-61000"}, got.Grants[0].IP)
}

func TestEnsureGrant_WildcardPortsSatisfy(t *testing.T) {
	raw := `{"grants":[{"src":["tag:mobile"],"dst":["tag:laptop"],"ip":["*"]}]}`
	e, err := tailscale.NewACLEditor([]byte(raw))
	require.NoError(t, err)

	before := append([]byte(nil), e.Bytes()...)
	require.NoError(t, e.EnsureGrant())
	assert.Equal(t, string(before), string(e.Bytes()), "a wildcard grant covers all required ports — no-op")
}

func TestEnsureGrant_PortsSplitAcrossGrants(t *testing.T) {
	// The union of all mobile→laptop grants covers the required set — no edit.
	raw := `{"grants":[
		{"src":["tag:mobile"],"dst":["tag:laptop"],"ip":["tcp:22","tcp:2586"]},
		{"src":["tag:mobile"],"dst":["tag:laptop"],"ip":["udp:60000-61000"]}
	]}`
	e, err := tailscale.NewACLEditor([]byte(raw))
	require.NoError(t, err)

	before := append([]byte(nil), e.Bytes()...)
	require.NoError(t, e.EnsureGrant())
	assert.Equal(t, string(before), string(e.Bytes()),
		"grants whose union covers the required ports must not be modified")
}

func TestEnsureSSHRule_RewritesAcceptToCheck(t *testing.T) {
	// A pre-existing action:"accept" rule is a no-reauth SSH path; it must
	// NEVER satisfy the check requirement (immutable 12h checkPeriod default).
	raw := `{"ssh":[{"action":"accept","src":["owner@example.com"],"dst":["tag:laptop"],"users":["macuser"]}]}`
	e, err := tailscale.NewACLEditor([]byte(raw))
	require.NoError(t, err)

	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))

	var got struct {
		SSH []struct {
			Action      string `json:"action"`
			CheckPeriod string `json:"checkPeriod"`
		} `json:"ssh"`
	}
	require.NoError(t, json.Unmarshal(e.Bytes(), &got))
	require.Len(t, got.SSH, 1, "the weak rule must be rewritten in place, not duplicated")
	assert.Equal(t, "check", got.SSH[0].Action, "accept must be rewritten to check")
	assert.Equal(t, "12h", got.SSH[0].CheckPeriod)
}

func TestEnsureSSHRule_ExistingCheckRuleIsNoOp(t *testing.T) {
	raw := `{"ssh":[{"action":"check","src":["owner@example.com"],"dst":["tag:laptop"],"users":["macuser"],"checkPeriod":"12h"}]}`
	e, err := tailscale.NewACLEditor([]byte(raw))
	require.NoError(t, err)

	before := append([]byte(nil), e.Bytes()...)
	require.NoError(t, e.EnsureSSHRule("owner@example.com", "macuser", "12h"))
	assert.Equal(t, string(before), string(e.Bytes()), "a matching check rule must be a no-op")
}

func TestDiff(t *testing.T) {
	old := []byte(`{"tagOwners": {}}`)
	nw := []byte(`{"tagOwners": {"tag:mobile": ["user@example.com"]}}`)

	diff := tailscale.Diff(old, nw)
	assert.NotEmpty(t, diff, "diff of different documents should be non-empty")
}

func TestDiff_Same(t *testing.T) {
	same := []byte(`{"tagOwners": {}}`)
	diff := tailscale.Diff(same, same)
	assert.Empty(t, diff, "diff of identical documents should be empty")
}

func TestDiff_DetectsDuplicatedLines(t *testing.T) {
	// The old set-membership diff was blind to duplicate-count changes.
	old := []byte("a\nb")
	nw := []byte("a\nb\nb")

	diff := tailscale.Diff(old, nw)
	assert.Equal(t, "+ b\n", diff, "a duplicated line must show up as an addition")
}

func TestDiff_DetectsReorderedLines(t *testing.T) {
	// The old set-membership diff was blind to reorderings.
	old := []byte("a\nb")
	nw := []byte("b\na")

	diff := tailscale.Diff(old, nw)
	assert.NotEmpty(t, diff, "reordered lines must produce a non-empty diff")
	assert.Contains(t, diff, "- ")
	assert.Contains(t, diff, "+ ")
}

func TestDiff_OrderedOutput(t *testing.T) {
	old := []byte("keep\nremove-me\nkeep2")
	nw := []byte("keep\nadd-me\nkeep2")

	diff := tailscale.Diff(old, nw)
	assert.Equal(t, "- remove-me\n+ add-me\n", diff,
		"diff must emit removals and additions in document order")
}
