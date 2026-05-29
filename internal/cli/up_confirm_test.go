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
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
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
