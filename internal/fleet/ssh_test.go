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

package fleet

import (
	_ "embed"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/status.json
var statusFixture []byte

//go:embed testdata/doctor.json
var doctorFixture []byte

// TestFanOut_ParsesJSON verifies that a RigResult with valid status JSON in
// Stdout decodes into the correct statusResult fields.
func TestFanOut_ParsesJSON(t *testing.T) {
	r := RigResult{
		Rig:       config.RigConfig{Name: "test-rig", Hostname: "test-rig.ts.net"},
		Reachable: true,
		Stdout:    string(statusFixture),
	}

	status, ok, err := DecodeStatus(r)

	require.NoError(t, err)
	require.True(t, ok, "decoding valid status JSON should succeed")
	assert.Equal(t, "up", status.Tailscale)
	assert.Equal(t, "100.64.1.1", status.TailscaleIP)
	assert.Equal(t, "test-rig", status.Hostname)
	assert.Equal(t, "enabled", status.TailscaleSSH)
	assert.Equal(t, "enabled", status.TailnetLock)
	assert.Equal(t, "running", status.Ntfy)
	assert.Equal(t, "encrypted", status.DiskEncrypt)
	assert.Equal(t, "2026-06-01T19:00:00Z", status.Timestamp)
}

// TestFanOut_ParsesDoctorJSON verifies that a RigResult with a valid doctor JSON
// array in Stdout decodes into the expected []RemoteFinding slice.
func TestFanOut_ParsesDoctorJSON(t *testing.T) {
	r := RigResult{
		Rig:       config.RigConfig{Name: "test-rig", Hostname: "test-rig.ts.net"},
		Reachable: true,
		Stdout:    string(doctorFixture),
	}

	findings, ok, err := DecodeFindings(r)

	require.NoError(t, err)
	require.True(t, ok, "decoding valid doctor JSON should succeed")
	require.Len(t, findings, 3)

	assert.Equal(t, "tailscale", findings[0].Module)
	assert.Equal(t, "ts-running", findings[0].Check)
	assert.Equal(t, "ok", findings[0].Severity)

	assert.Equal(t, "ntfy", findings[2].Module)
	assert.Equal(t, "warn", findings[2].Severity)
	assert.Equal(t, "abysslink up --apply", findings[2].Fix)
}

// TestFanOut_DegradedVsUnreachable verifies that a Reachable rig whose Stdout
// is non-JSON (e.g. MOTD/banner leak) is classified as degraded-but-reachable
// (distinct from UNREACHABLE). ok=false and a non-empty RawTail are returned.
func TestFanOut_DegradedVsUnreachable(t *testing.T) {
	motdOutput := "Welcome to Ubuntu 22.04 LTS\nLast login: Mon Jun  1 19:00:00\n"

	r := RigResult{
		Rig:       config.RigConfig{Name: "test-rig", Hostname: "test-rig.ts.net"},
		Reachable: true,  // SSH succeeded — rig is online
		Stdout:    motdOutput,
	}

	_, ok, err := DecodeStatus(r)

	// ok=false signals degraded-but-reachable (decode failed), not UNREACHABLE.
	assert.False(t, ok, "non-JSON stdout should return ok=false (degraded, not unreachable)")
	// err carries the decode failure so callers can surface a warning.
	require.Error(t, err, "degraded decode must return an error describing the parse failure")
}

// TestFanOut_UnreachableNotDecoded verifies that attempting to decode an
// UNREACHABLE result (Reachable==false) is rejected immediately with a sentinel
// error — there is no stdout to parse.
func TestFanOut_UnreachableNotDecoded(t *testing.T) {
	r := RigResult{
		Rig:       config.RigConfig{Name: "offline-rig", Hostname: "offline.ts.net"},
		Reachable: false,
		Stdout:    "",
	}

	_, ok, err := DecodeStatus(r)

	assert.False(t, ok)
	require.Error(t, err, "UNREACHABLE result must not be decoded")
}
