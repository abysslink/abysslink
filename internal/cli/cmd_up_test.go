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
	"github.com/stretchr/testify/require"
)

// unknownDiskFinding returns a FATAL hardening finding that carries the
// Plan 02 UNKNOWN-state marker substring ("disk-encryption state is UNKNOWN").
// The gate in cmd_up.go must detect this substring and refuse --force-unsafe.
func unknownDiskFinding() modules.Finding {
	return modules.Finding{
		Module:   "hardening",
		Check:    "filevault",
		Severity: modules.SeverityFatal,
		Message:  "disk-encryption state is UNKNOWN — fdesetup returned unexpected output; verify encryption manually",
	}
}

// knownOffDiskFinding returns a FATAL hardening finding that does NOT carry the
// UNKNOWN marker — it represents a disk that is known to be fully unencrypted.
// The existing --force-unsafe path must still bypass this (preserved behavior).
func knownOffDiskFinding() modules.Finding {
	return modules.Finding{
		Module:   "hardening",
		Check:    "filevault",
		Severity: modules.SeverityFatal,
		Message:  "FileVault is Off — full-disk encryption is required",
	}
}

// TestUpDiskEncryption_UnknownBlocksWithForceUnsafe asserts that a FATAL
// disk-encryption finding carrying the UNKNOWN-state marker ("disk-encryption
// state is UNKNOWN") blocks up EVEN when --force-unsafe is set. This is the
// D-05 / CLAUDE.md immutable default: unknown state is non-overridable.
//
// RED gate: this fails until the gate distinguishes UNKNOWN from known-off.
func TestUpDiskEncryption_UnknownBlocksWithForceUnsafe(t *testing.T) {
	blockers := []modules.Finding{unknownDiskFinding()}
	err := diskEncryptionGate(blockers, true /* forceUnsafe */)
	require.Error(t, err, "unknown disk-encryption state must block up even with --force-unsafe")
	// The error message must explain manual verification, NOT offer --force-unsafe as a bypass.
	assert.NotContains(t, err.Error(), "--force-unsafe",
		"unknown-state error must NOT mention --force-unsafe as a way out")
	assert.True(t,
		strings.Contains(err.Error(), "verify") || strings.Contains(err.Error(), "manual"),
		"unknown-state error must explain how to verify encryption manually")
}

// TestUpDiskEncryption_UnknownBlocksWithoutForceUnsafe asserts that a
// UNKNOWN-state finding blocks up regardless of whether --force-unsafe is set.
func TestUpDiskEncryption_UnknownBlocksWithoutForceUnsafe(t *testing.T) {
	blockers := []modules.Finding{unknownDiskFinding()}
	err := diskEncryptionGate(blockers, false /* forceUnsafe */)
	require.Error(t, err, "unknown disk-encryption state must block up without --force-unsafe")
}

// TestUpDiskEncryption_KnownOffAllowsForceUnsafe asserts that a known-off
// (fully unencrypted, NOT unknown) FATAL finding is still bypassable via
// --force-unsafe — the pre-existing behavior must be preserved.
func TestUpDiskEncryption_KnownOffAllowsForceUnsafe(t *testing.T) {
	blockers := []modules.Finding{knownOffDiskFinding()}
	err := diskEncryptionGate(blockers, true /* forceUnsafe */)
	assert.NoError(t, err, "known-off (not unknown) disk-encryption state must be bypassable with --force-unsafe")
}

// TestUpDiskEncryption_NoBlockers asserts that an empty blocker slice
// returns no error regardless of --force-unsafe.
func TestUpDiskEncryption_NoBlockers(t *testing.T) {
	assert.NoError(t, diskEncryptionGate(nil, false))
	assert.NoError(t, diskEncryptionGate(nil, true))
}
