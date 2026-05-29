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
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatusJSONNoANSI verifies that printing a statusReport via PrintJSON produces
// ANSI-free output that round-trips through json.Unmarshal.
func TestStatusJSONNoANSI(t *testing.T) {
	rep := statusReport{
		Tailscale:    "running",
		TailscaleIP:  "100.64.1.2",
		Hostname:     "myrig",
		TailscaleSSH: "enabled",
		TailnetLock:  "enabled",
		Ntfy:         "enabled",
		DiskEncrypt:  "encrypted",
		Timestamp:    "2026-05-29 14:00",
	}

	var buf bytes.Buffer
	p := NewJSONPrinterTo(&buf, &buf)
	p.PrintJSON(rep)

	output := buf.String()

	// No ANSI escape bytes must appear.
	assert.False(t, strings.Contains(output, "\x1b"),
		"status --json output must contain no ANSI ESC bytes; got: %q", output)

	// Must round-trip cleanly.
	var decoded statusReport
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &decoded))
	assert.Equal(t, "running", decoded.Tailscale)
	assert.Equal(t, "100.64.1.2", decoded.TailscaleIP)
	assert.Equal(t, "myrig", decoded.Hostname)
	assert.Equal(t, "enabled", decoded.TailscaleSSH)
	assert.Equal(t, "enabled", decoded.TailnetLock)
	assert.Equal(t, "enabled", decoded.Ntfy)
	assert.Equal(t, "encrypted", decoded.DiskEncrypt)
}

// TestStatusJSONFieldNames verifies that JSON field names match the documented schema.
func TestStatusJSONFieldNames(t *testing.T) {
	rep := statusReport{
		Tailscale:    "running",
		TailscaleSSH: "enabled",
		TailnetLock:  "enabled",
		Ntfy:         "enabled",
		DiskEncrypt:  "encrypted",
		Timestamp:    "2026-05-29 14:00",
	}

	var buf bytes.Buffer
	p := NewJSONPrinterTo(&buf, &buf)
	p.PrintJSON(rep)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &raw))

	// Verify expected top-level keys exist.
	for _, key := range []string{"tailscale", "tailscale_ssh", "tailnet_lock", "ntfy", "disk_encrypt", "timestamp"} {
		assert.Contains(t, raw, key, "JSON output must have field %q", key)
	}
}
