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
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestSudoKeywords_ExtractsMatchingActions asserts that sudoKeywords returns
// only the actions whose descriptions or module names contain known sudo keywords.
func TestSudoKeywords_ExtractsMatchingActions(t *testing.T) {
	actions := []modules.Action{
		{Module: "power", Description: "set pmset hibernation mode"},
		{Module: "ssh", Description: "write authorized_keys"},
		{Module: "hardening", Description: "enable socketfilterfw"},
		{Module: "tmux", Description: "install tmux plugin manager"},
	}
	got := sudoActionsFromActions(actions)
	// pmset and socketfilterfw match; ssh and tmux do not.
	assert.Len(t, got, 2)
	for _, s := range got {
		assert.True(t,
			strings.Contains(strings.ToLower(s), "pmset") ||
				strings.Contains(strings.ToLower(s), "socketfilterfw"),
			"got unexpected sudo action: %q", s,
		)
	}
}

// TestSudoKeywords_EmptyWhenNoMatch asserts an empty slice when no actions match.
func TestSudoKeywords_EmptyWhenNoMatch(t *testing.T) {
	actions := []modules.Action{
		{Module: "ssh", Description: "write sshd_config"},
		{Module: "tmux", Description: "configure tmux.conf"},
	}
	got := sudoActionsFromActions(actions)
	assert.Empty(t, got)
}

// TestApplyRenderRow_ContainsModuleName asserts that the plain apply render row
// contains the module name and [N/M] counter.
func TestApplyRenderRow_ContainsModuleName(t *testing.T) {
	evt := modules.ModuleEvent{
		Module:   "tailscale",
		Index:    1,
		Total:    3,
		Findings: nil,
		ApplyErr: nil,
	}
	out := applyRowStr(evt)
	assert.Contains(t, out, "tailscale")
	assert.Contains(t, out, "[1/3]")
}

// TestScanRenderRow_ContainsModuleName asserts that the plain scan render row
// contains the module name.
func TestScanRenderRow_ContainsModuleName(t *testing.T) {
	evt := modules.ModuleEvent{
		Module:  "ssh",
		Index:   2,
		Total:   5,
		Actions: nil,
	}
	out := scanRowStr(evt)
	assert.Contains(t, out, "ssh")
}

// TestApplyAnimationEnabled_DisabledWhenSudoPresent is the Phase 10 stdin-race
// regression guard. Before the fix, the apply phase chose between the live tea
// table and the plain Printer path purely from jsonOut + TTY. When a module
// required sudo (`pmset`, `socketfilterfw`, …) the tea program owned os.Stdin
// while sudo also wired cmd.Stdin = os.Stdin, racing for password bytes.
//
// The fix gates apply animation on the absence of sudo: if any planned action
// requires sudo, force the plain Printer path so the password prompt can read
// stdin unmolested. Scan-phase animation is unaffected.
func TestApplyAnimationEnabled_DisabledWhenSudoPresent(t *testing.T) {
	sudo := []string{"power              set pmset hibernation mode"}
	// Even with jsonOut=false (the case where animation would otherwise be
	// considered), the presence of any sudo line forces the plain path.
	assert.False(t, applyAnimationEnabled(false, sudo),
		"apply animation must be disabled whenever sudo is required")
}

// TestApplyAnimationEnabled_DisabledInJSONMode asserts JSON mode always wins —
// even with no sudo lines we never animate when emitting structured output.
func TestApplyAnimationEnabled_DisabledInJSONMode(t *testing.T) {
	assert.False(t, applyAnimationEnabled(true, nil),
		"apply animation must be disabled in JSON mode")
}

// TestApplyAnimationEnabled_DisabledWhenNotTTY asserts the predicate defers to
// the underlying animationEnabled() gate when no sudo is required. In test
// environments stdout is not a TTY, so animation is disabled — matching
// TestAnimationEnabled_NotInTest in term_test.go.
func TestApplyAnimationEnabled_DisabledWhenNotTTY(t *testing.T) {
	// Headless test environment: animationEnabled(false) returns false,
	// so applyAnimationEnabled returns false too.
	assert.False(t, applyAnimationEnabled(false, nil),
		"apply animation requires both no-sudo AND animationEnabled()=true")
}

// TestApplyAnimationEnabled_PerSudoKeyword exhaustively asserts that any
// non-empty sudo list — regardless of which keyword matched — forces the plain
// path. Keeps the predicate from being accidentally narrowed to one keyword.
func TestApplyAnimationEnabled_PerSudoKeyword(t *testing.T) {
	allKeywords := []modules.Action{
		{Module: "power", Description: "pmset something"},
		{Module: "linuxd", Description: "systemctl enable foo"},
		{Module: "hardening", Description: "socketfilterfw blockall"},
	}
	for _, action := range allKeywords {
		sudo := sudoActionsFromActions([]modules.Action{action})
		assert.NotEmpty(t, sudo,
			"sudoActionsFromActions must classify %q as sudo", action.Description)
		assert.False(t, applyAnimationEnabled(false, sudo),
			"apply animation must stay disabled for %q", action.Description)
	}
}

// TestRunApply_AbortContract is a compile-time witness that runApply returns
// four values: ([]modules.Finding, time.Duration, bool, error).
// If the signature changes, this file will fail to compile, catching regressions
// before any runtime test is invoked.
func TestRunApply_AbortContract(t *testing.T) {
	// This test exists solely to assert the function signature. The variable
	// assignment below is a zero-cost compile check — it does not invoke runApply.
	var _ func(context.Context, *cobra.Command, Printer, *modules.Runner, []modules.Action, *cmdContext) ([]modules.Finding, time.Duration, bool, error) = runApply
	t.Log("runApply signature is (ctx, cmd, Printer, *Runner, []Action, *cmdContext) ([]Finding, Duration, bool, error)")
}
