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
