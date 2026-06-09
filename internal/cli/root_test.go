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
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRigFlagsCmd builds a throwaway command carrying the fleet-targeting flags
// that resolveRigTargets reads (they are persistent root flags in production).
func newRigFlagsCmd(t *testing.T, rig string, allRigs bool) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("rig", "", "")
	cmd.Flags().Bool("all-rigs", false, "")
	if rig != "" {
		require.NoError(t, cmd.Flags().Set("rig", rig))
	}
	if allRigs {
		require.NoError(t, cmd.Flags().Set("all-rigs", "true"))
	}
	return cmd
}

// TestResolveRigTargets_SingleRig verifies the CLI-05 fix: --rig X selects
// exactly the named enrolled rig, marks the run remote-only, and never falls
// through to silent local execution.
func TestResolveRigTargets_SingleRig(t *testing.T) {
	enrolled := []config.RigConfig{
		{Name: "alpha", NtfyTopic: "topic-a"},
		{Name: "beta", NtfyTopic: "topic-b"},
	}

	rt, err := resolveRigTargets(newRigFlagsCmd(t, "beta", false), enrolled)
	require.NoError(t, err)
	assert.True(t, rt.fanOut, "--rig must request fan-out")
	assert.True(t, rt.rigOnly, "--rig must skip local execution")
	require.Len(t, rt.rigs, 1, "--rig must target exactly one rig")
	assert.Equal(t, "beta", rt.rigs[0].Name)
}

// TestResolveRigTargets_UnknownRig verifies that an unknown --rig name is a
// hard error listing the enrolled rigs — never a silent local run (CLI-05:
// `panic --rig laptop` used to silently run LOCAL panic).
func TestResolveRigTargets_UnknownRig(t *testing.T) {
	enrolled := []config.RigConfig{{Name: "alpha"}}

	rt, err := resolveRigTargets(newRigFlagsCmd(t, "laptop", false), enrolled)
	require.Error(t, err, "unknown rig name must error, not fall back to local")
	assert.Contains(t, err.Error(), `"laptop"`)
	assert.Contains(t, err.Error(), "alpha", "error must list enrolled rigs")
	assert.False(t, rt.fanOut)
}

// TestResolveRigTargets_NoRigsEnrolled verifies --rig with zero enrolled rigs
// errors with enrollment guidance.
func TestResolveRigTargets_NoRigsEnrolled(t *testing.T) {
	_, err := resolveRigTargets(newRigFlagsCmd(t, "laptop", false), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rigs are enrolled")
}

// TestResolveRigTargets_AllRigs verifies --all-rigs preserves the existing
// fan-out-to-everyone semantics (local execution NOT skipped).
func TestResolveRigTargets_AllRigs(t *testing.T) {
	enrolled := []config.RigConfig{{Name: "alpha"}, {Name: "beta"}}

	rt, err := resolveRigTargets(newRigFlagsCmd(t, "", true), enrolled)
	require.NoError(t, err)
	assert.True(t, rt.fanOut)
	assert.False(t, rt.rigOnly, "--all-rigs must keep local execution")
	assert.Len(t, rt.rigs, 2)
}

// TestResolveRigTargets_Neither verifies the default local-only path.
func TestResolveRigTargets_Neither(t *testing.T) {
	rt, err := resolveRigTargets(newRigFlagsCmd(t, "", false), []config.RigConfig{{Name: "alpha"}})
	require.NoError(t, err)
	assert.False(t, rt.fanOut)
	assert.False(t, rt.rigOnly)
	assert.Empty(t, rt.rigs)
}

// TestResolveRigTargets_MutuallyExclusive verifies --rig + --all-rigs is rejected.
func TestResolveRigTargets_MutuallyExclusive(t *testing.T) {
	_, err := resolveRigTargets(newRigFlagsCmd(t, "alpha", true), []config.RigConfig{{Name: "alpha"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
