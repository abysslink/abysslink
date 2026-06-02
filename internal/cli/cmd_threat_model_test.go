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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runThreatModel executes the threat-model command with the given args and
// returns its captured stdout. The doctor pass inside RunE is best-effort and
// degrades gracefully in the test environment (no rig configured), so every
// row renders with ✓ and the row descriptions are present in the output.
func runThreatModel(t *testing.T, args ...string) string {
	t.Helper()
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"threat-model"}, args...))
	require.NoError(t, root.Execute())
	return out.String()
}

func TestThreatModelBackend(t *testing.T) {
	// Representative base + v3 row substrings present in all renderings.
	baseRows := []string{
		"No public exposure (no Funnel)",
		"Tailnet Lock enabled",
	}
	v3Rows := []string{
		"sec-metrics-bind",
		"sec-webui-bind",
		"sec-audit-anchor-age",
	}

	t.Run("no_backend", func(t *testing.T) {
		out := runThreatModel(t)
		for _, r := range baseRows {
			assert.Contains(t, out, r)
		}
		for _, r := range v3Rows {
			assert.Contains(t, out, r)
		}
		// No backend-specific section headers.
		assert.NotContains(t, out, "Backend: tailscale")
		assert.NotContains(t, out, "Backend: headscale")
		assert.NotContains(t, out, "Backend: netbird")
	})

	t.Run("tailscale", func(t *testing.T) {
		out := runThreatModel(t, "--backend=tailscale")
		for _, r := range v3Rows {
			assert.Contains(t, out, r)
		}
		assert.Contains(t, out, "Backend: tailscale")
		for _, r := range []string{"Tailnet Lock enabled", "ACL policy not drifted", "sec-funnel-schema"} {
			assert.Contains(t, out, r)
		}
	})

	t.Run("headscale", func(t *testing.T) {
		out := runThreatModel(t, "--backend=headscale")
		for _, r := range v3Rows {
			assert.Contains(t, out, r)
		}
		assert.Contains(t, out, "Backend: headscale")
		for _, r := range []string{"hs-tls", "hs-api-auth", "hs-lock", "hs-oidc-filter"} {
			assert.Contains(t, out, r)
		}
	})

	t.Run("netbird", func(t *testing.T) {
		out := runThreatModel(t, "--backend=netbird")
		for _, r := range v3Rows {
			assert.Contains(t, out, r)
		}
		assert.Contains(t, out, "Backend: netbird")
		for _, r := range []string{"nb-tls", "nb-version", "nb-zitadel", "nb-lock"} {
			assert.Contains(t, out, r)
		}
	})

	t.Run("invalid_backend", func(t *testing.T) {
		// Unknown backend renders base + v3 rows only, emits a warning, no panic/error.
		out := runThreatModel(t, "--backend=foobar")
		for _, r := range baseRows {
			assert.Contains(t, out, r)
		}
		for _, r := range v3Rows {
			assert.Contains(t, out, r)
		}
		assert.True(t, strings.Contains(out, "unknown backend"),
			"expected an unknown-backend warning in output")
	})
}
