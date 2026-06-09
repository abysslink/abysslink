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
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// applyFlagsCmd returns a bare command carrying the --dry-run/--apply flags so
// resolveApplyFlags can be exercised without the full root command.
func applyFlagsCmd(t *testing.T, dryRun, apply bool) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("apply", false, "")
	if dryRun {
		require.NoError(t, cmd.Flags().Set("dry-run", "true"))
	}
	if apply {
		require.NoError(t, cmd.Flags().Set("apply", "true"))
	}
	return cmd
}

// TestResolveApplyFlags covers the CLI-09 matrix: default → dry-run,
// --apply → apply, --dry-run → dry-run, both → error.
func TestResolveApplyFlags(t *testing.T) {
	// Neither flag: dry-run is the default (CLAUDE.md hard rule #7).
	dryRun, apply, err := resolveApplyFlags(applyFlagsCmd(t, false, false))
	require.NoError(t, err)
	assert.True(t, dryRun)
	assert.False(t, apply)

	// --apply only.
	dryRun, apply, err = resolveApplyFlags(applyFlagsCmd(t, false, true))
	require.NoError(t, err)
	assert.False(t, dryRun)
	assert.True(t, apply)

	// --dry-run only.
	dryRun, apply, err = resolveApplyFlags(applyFlagsCmd(t, true, false))
	require.NoError(t, err)
	assert.True(t, dryRun)
	assert.False(t, apply)

	// Both: contradictory — rejected (CLI-09).
	_, _, err = resolveApplyFlags(applyFlagsCmd(t, true, true))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestLoadCmdContext_DryRunApplyMutuallyExclusive asserts that any command
// going through loadCmdContext rejects the --dry-run --apply combination.
func TestLoadCmdContext_DryRunApplyMutuallyExclusive(t *testing.T) {
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"rig", "ls", "--dry-run", "--apply"})

	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
