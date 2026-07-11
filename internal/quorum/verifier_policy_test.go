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

package quorum

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
)

// checkV2 runs V2 over one argv.
func checkV2(t *testing.T, extraPaths, extraBranches []string, name string, args ...string) Vote {
	t.Helper()
	v := newPolicyVerifier(extraPaths, extraBranches)
	return v.check(context.Background(), action{name: name, args: args, binary: filepath.Base(name)})
}

func TestPolicy_ProtectedPathWriteIsCritical(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	v := checkV2(t, nil, nil, "rm", "-rf", filepath.Join(home, ".ssh", "authorized_keys"))
	assert.Equal(t, VerdictEscalate, v.Verdict)
	assert.Equal(t, approve.TierCritical, v.Tier)
	assert.Equal(t, codeProtectedPathWrite, v.Code)
	assert.Contains(t, v.Reason, "~/.ssh", "the reason must name the protected LABEL")
	assert.NotContains(t, v.Reason, "authorized_keys", "the reason must never carry the raw argument")

	v = checkV2(t, nil, nil, "tee", "/etc/hosts")
	assert.Equal(t, codeProtectedPathWrite, v.Code)
	assert.Contains(t, v.Reason, "/etc")
}

func TestPolicy_AddOnlyConfigPaths(t *testing.T) {
	v := checkV2(t, []string{"/srv/prod-inventory"}, nil, "rm", "-rf", "/srv/prod-inventory/db")
	assert.Equal(t, VerdictEscalate, v.Verdict)
	assert.Equal(t, approve.TierCritical, v.Tier)
	assert.Contains(t, v.Reason, "/srv/prod-inventory", "config labels are allowed in reasons (operator-provided)")
}

func TestPolicy_ForcePushProtectedBranch(t *testing.T) {
	v := checkV2(t, nil, nil, "git", "push", "--force", "origin", "main")
	assert.Equal(t, VerdictEscalate, v.Verdict)
	assert.Equal(t, approve.TierCritical, v.Tier)
	assert.Equal(t, codeForcePushProtected, v.Code)

	// Add-only config branch.
	v = checkV2(t, nil, []string{"release"}, "git", "push", "-f", "origin", "release")
	assert.Equal(t, codeForcePushProtected, v.Code)

	// Non-forced push to main is fine for V2.
	v = checkV2(t, nil, nil, "git", "push", "origin", "main")
	assert.Equal(t, VerdictAllow, v.Verdict)
	assert.Equal(t, ConfidenceHigh, v.Confidence)
}

func TestPolicy_AmbiguityNeverConfidentlyAllows(t *testing.T) {
	t.Run("parent traversal", func(t *testing.T) {
		v := checkV2(t, nil, nil, "rm", "-rf", "work/../../.ssh")
		assert.Equal(t, VerdictAllow, v.Verdict)
		assert.Equal(t, ConfidenceLow, v.Confidence, ".. traversal must degrade to Low confidence")
		assert.Equal(t, codeAmbiguousScope, v.Code)
		assert.Equal(t, OutcomeEscalate, effectiveOutcome(v), "the lattice must escalate ALLOW@Low")
	})

	t.Run("glob into protected scope", func(t *testing.T) {
		home, err := os.UserHomeDir()
		require.NoError(t, err)
		v := checkV2(t, nil, nil, "rm", "-f", filepath.Join(home, ".ssh")+"/*")
		assert.Equal(t, ConfidenceLow, v.Confidence)
		assert.Equal(t, codeAmbiguousScope, v.Code)
	})

	t.Run("homoglyph / non-ASCII path", func(t *testing.T) {
		v := checkV2(t, nil, nil, "rm", "-rf", "~/.ssh\u200b") // zero-width space
		assert.Equal(t, ConfidenceLow, v.Confidence)
		assert.Equal(t, codeNonASCIIPath, v.Code)
	})

	t.Run("write verb with no parseable target", func(t *testing.T) {
		v := checkV2(t, nil, nil, "rm", "-rf")
		assert.Equal(t, ConfidenceLow, v.Confidence, "a policy-relevant parse gap can never confidently allow")
		assert.Equal(t, codeParseGap, v.Code)
	})
}

func TestPolicy_BenignAllowsConfidently(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		{"ls", "-la"},
		{"git", "status"},
		{"rm", filepath.Join(dir, "scratch.txt")}, // workspace write, unprotected
		{"cat", "/etc/hosts"},                     // read verb on a protected path
	}
	for _, argv := range cases {
		v := checkV2(t, nil, nil, argv[0], argv[1:]...)
		assert.Equal(t, VerdictAllow, v.Verdict, "%v", argv)
		assert.Equal(t, ConfidenceHigh, v.Confidence, "%v", argv)
	}
}

func TestParseIntent_NormalizedModel(t *testing.T) {
	in := parseIntent(action{binary: "git", args: []string{"push", "--force", "origin", "main"}})
	assert.Equal(t, "git", in.binary)
	assert.Equal(t, "push", in.subcommand)
	assert.Equal(t, []string{"--force"}, in.flags)
	assert.Equal(t, []string{"origin", "main"}, in.targets)

	in = parseIntent(action{binary: "dd", args: []string{"if=/dev/zero", "of=/tmp/img"}})
	assert.Equal(t, []string{"/tmp/img"}, in.targets, "dd of= is the write target; if= is not")
}
