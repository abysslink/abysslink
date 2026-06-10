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

package notifyv2_test

import (
	"os"
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/conformance"
	"github.com/abysslink/abysslink/internal/notifyv2"
)

// validULID is the canonical oklog/ulid example string; passes ParseStrict.
const validULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// wellFormed returns a fully-populated valid v2 message.
func wellFormed() notifyv2.Message {
	return notifyv2.Message{
		V:     2,
		MsgID: validULID,
		Kind:  notifyv2.KindNeedsInput,
		Host:  "rig-1",
		Session: notifyv2.SessionRef{
			Session: "$1",
			Window:  "@2",
			Pane:    "%3",
			Epoch:   1,
		},
		Consumer: "claudecode",
		Title:    "needs input",
		DeepLink: "abysslink://attach?host=rig-1&session=$1&window=@2&pane=%253",
		Fetch: &notifyv2.FetchRef{
			URLTailnet: "https://100.110.12.7:9869/content/" + validULID,
			TTLSeconds: 600,
		},
		Priority: "high",
		Actions: []notifyv2.Action{
			{ID: "approve", Label: "Approve"},
			{ID: "deny", Label: "Deny"},
		},
	}
}

func TestValidate_Valid(t *testing.T) {
	cases := []struct {
		name string
		msg  notifyv2.Message
	}{
		{name: "fully populated", msg: wellFormed()},
		{
			// Hook/CLI consumers outside tmux: no session identity at all.
			name: "minimal: empty SessionRef, no consumer, no fetch",
			msg: notifyv2.Message{
				V:     2,
				MsgID: validULID,
				Kind:  notifyv2.KindCommandDone,
				Host:  "rig-1",
				Title: "done ✓",
			},
		},
		{
			name: "ts.net fetch host and normal priority",
			msg: func() notifyv2.Message {
				m := wellFormed()
				m.Fetch = &notifyv2.FetchRef{
					URLTailnet: "https://rig-1.tail1234.ts.net/content/" + validULID,
					TTLSeconds: 60,
				}
				m.Priority = "normal"
				return m
			}(),
		},
		{
			// Tailscale IPv6 tailnet addresses live in the ULA prefix
			// fd7a:115c:a1e0::/48 — they must be accepted as fetch hosts.
			name: "ipv6 tailnet ULA fetch host",
			msg: func() notifyv2.Message {
				m := wellFormed()
				m.Fetch = &notifyv2.FetchRef{
					URLTailnet: "https://[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:9869/content/" + validULID,
					TTLSeconds: 60,
				}
				return m
			}(),
		},
		{
			// Empty host is valid — the daemon enriches it server-side.
			name: "empty host",
			msg: func() notifyv2.Message {
				m := wellFormed()
				m.Host = ""
				return m
			}(),
		},
		{
			// Hostname shapes with dots and uppercase stay valid.
			name: "fqdn-ish host",
			msg: func() notifyv2.Message {
				m := wellFormed()
				m.Host = "Rig-1.local"
				return m
			}(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.msg
			assert.NoError(t, msg.Validate())
		})
	}
}

func TestValidate_Invalid(t *testing.T) {
	mut := func(f func(*notifyv2.Message)) notifyv2.Message {
		m := wellFormed()
		f(&m)
		return m
	}

	cases := []struct {
		name string
		msg  notifyv2.Message
		want string // substring the error must contain (offending field)
	}{
		{"v not 2", mut(func(m *notifyv2.Message) { m.V = 1 }), "v"},
		{"empty msg_id", mut(func(m *notifyv2.Message) { m.MsgID = "" }), "msg_id"},
		{"malformed msg_id", mut(func(m *notifyv2.Message) { m.MsgID = "not-a-ulid" }), "msg_id"},
		{"unknown kind", mut(func(m *notifyv2.Message) { m.Kind = "shoulder_tap" }), "kind"},
		{"empty title", mut(func(m *notifyv2.Message) { m.Title = "" }), "title"},
		{"title over 200 chars", mut(func(m *notifyv2.Message) { m.Title = strings.Repeat("a", 201) }), "title"},
		{"title with LF (header injection)", mut(func(m *notifyv2.Message) { m.Title = "needs input\nX-Priority: 5" }), "title"},
		{"title with CRLF", mut(func(m *notifyv2.Message) { m.Title = "needs\r\ninput" }), "title"},
		{"host smuggles pane content", mut(func(m *notifyv2.Message) {
			m.Host = "FAILED: rm -rf ~/src exited 1 — see transcript"
		}), "host"},
		{"host with newline", mut(func(m *notifyv2.Message) { m.Host = "rig-1\nleaked line" }), "host"},
		{"host over 63 chars", mut(func(m *notifyv2.Message) { m.Host = "h" + strings.Repeat("o", 63) }), "host"},
		{"host leading hyphen", mut(func(m *notifyv2.Message) { m.Host = "-rig" }), "host"},
		{"consumer uppercase and space", mut(func(m *notifyv2.Message) { m.Consumer = "Claude Code" }), "consumer"},
		{"session id wrong shape", mut(func(m *notifyv2.Message) { m.Session.Session = "$x" }), "session"},
		{"window id missing @", mut(func(m *notifyv2.Message) { m.Session.Window = "5" }), "window"},
		{"pane id missing percent", mut(func(m *notifyv2.Message) { m.Session.Pane = "3" }), "pane"},
		{"deep_link https scheme", mut(func(m *notifyv2.Message) { m.DeepLink = "https://evil.example/attach" }), "deep_link"},
		{"deep_link over 512 bytes", mut(func(m *notifyv2.Message) {
			m.DeepLink = "abysslink://attach?x=" + strings.Repeat("a", 512)
		}), "deep_link"},
		{"deep_link with control char", mut(func(m *notifyv2.Message) {
			m.DeepLink = "abysslink://attach?x=1\nsmuggled"
		}), "deep_link"},
		{"fetch url http scheme", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "http://100.110.12.7/content/x", TTLSeconds: 60}
		}), "fetch"},
		{"fetch host off tailnet", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "https://example.com/content/x", TTLSeconds: 60}
		}), "fetch"},
		{"fetch ipv6 host off tailnet ULA", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "https://[2001:db8::1]/content/x", TTLSeconds: 60}
		}), "fetch"},
		{"fetch ipv6 host in non-tailscale ULA space", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "https://[fd00::1]/content/x", TTLSeconds: 60}
		}), "fetch"},
		{"fetch ttl zero", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "https://100.110.12.7/content/x", TTLSeconds: 0}
		}), "fetch"},
		{"priority urgent not allowed on wire", mut(func(m *notifyv2.Message) { m.Priority = "urgent" }), "priority"},
		{"unknown action id", mut(func(m *notifyv2.Message) { m.Actions = []notifyv2.Action{{ID: "reboot"}} }), "action"},
		{"action label over 64 runes", mut(func(m *notifyv2.Message) {
			m.Actions = []notifyv2.Action{{ID: "approve", Label: strings.Repeat("a", 65)}}
		}), "label"},
		{"action label with control char", mut(func(m *notifyv2.Message) {
			m.Actions = []notifyv2.Action{{ID: "approve", Label: "ok\napprove"}}
		}), "label"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.msg
			err := msg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want,
				"error should name the offending field: %v", err)
		})
	}
}

// TestValidate_SecretScan asserts that secret-shaped values in ANY string
// field are rejected (D-17 — no bypass path). The fixture lines each match a
// conformance secret pattern.
func TestValidate_SecretScan(t *testing.T) {
	data, err := os.ReadFile("testdata/secrets.txt")
	require.NoError(t, err)
	var lines []string
	for l := range strings.SplitSeq(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	require.NotEmpty(t, lines)

	// Each fixture line injected into Title must be rejected.
	for _, line := range lines {
		t.Run("title/"+line, func(t *testing.T) {
			m := wellFormed()
			m.Title = line
			err := m.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "secret")
		})
	}

	// Spot-check the other string fields (host, deep_link, action label).
	fieldCases := []struct {
		name string
		msg  notifyv2.Message
	}{
		{"host carries password", func() notifyv2.Message {
			m := wellFormed()
			m.Host = "password: hunter22"
			return m
		}()},
		{"deep_link carries api key", func() notifyv2.Message {
			m := wellFormed()
			m.DeepLink = "abysslink://attach?api_key=deadbeefcafe1234"
			return m
		}()},
		{"action label carries token", func() notifyv2.Message {
			m := wellFormed()
			m.Actions = []notifyv2.Action{{ID: "approve", Label: "token=abcdef0123456789abcdef"}}
			return m
		}()},
		{"fetch url carries secret", func() notifyv2.Message {
			m := wellFormed()
			m.Fetch = &notifyv2.FetchRef{
				URLTailnet: "https://100.110.12.7/content/x?secret=0123456789abcdef01234567",
				TTLSeconds: 60,
			}
			return m
		}()},
	}
	for _, tc := range fieldCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.msg
			err := msg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "secret")
		})
	}
}

// TestValidate_BareSecretTokens asserts that bare provider-prefixed token
// values — no key= or key: shape around them — are rejected in any string
// field, and that the rejection error never echoes the token (D-17 + the
// "no secrets in logs" hard rule: the daemon logs Validate errors verbatim).
// Tokens are assembled at runtime so no literal token shape sits in source.
func TestValidate_BareSecretTokens(t *testing.T) {
	tokens := []struct {
		name  string
		token string
	}{
		{"tailscale auth key", "tskey-auth-" + "kFGiAS1CNTRL-Xq8r2vZx9w"},
		{"tailscale disablement key", "tskey-disablement-" + "aabbccddee112233"},
		{"github classic token", "ghp_" + strings.Repeat("Ab1Cd2", 6)},
		{"github fine-grained token", "github_pat_" + strings.Repeat("9zY8xW", 6)},
		{"aws access key id", "AKIA" + "IOSFODNN" + "7EXAMPLE"},
		{"slack bot token", "xoxb-" + "123456789012-abcdefghijklmnop"},
	}
	for _, tk := range tokens {
		t.Run("title/"+tk.name, func(t *testing.T) {
			m := wellFormed()
			m.Title = "command done: " + tk.token
			err := m.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "secret")
			assert.NotContains(t, err.Error(), tk.token,
				"rejection error must not echo the token")
		})
	}

	// A bare token in Host must also be rejected — and rejected by the
	// secret scan (generic error), not by a shape check that echoes it.
	t.Run("host/tailscale auth key", func(t *testing.T) {
		m := wellFormed()
		m.Host = "tskey-auth-" + "kFGiAS1CNTRL-Xq8r2vZx9w"
		err := m.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret")
		assert.NotContains(t, err.Error(), "kFGiAS1CNTRL-Xq8r2vZx9w",
			"rejection error must not echo the token value")
	})
}

// TestValidate_ErrorsNeverEchoFieldValues asserts the no-echo invariant for
// shape-check errors: the daemon copies Validate errors into its log and 422
// bodies, so a malformed field carrying a token must never have its value
// reproduced in the error string.
func TestValidate_ErrorsNeverEchoFieldValues(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*notifyv2.Message)
		echoSub string // substring of the field value that must NOT appear
	}{
		{
			// Secret-bearing value: scanSecrets runs first and rejects
			// generically before the msg_id ULID shape check could echo it.
			name:    "msg_id carrying a tailscale key",
			mutate:  func(m *notifyv2.Message) { m.MsgID = "tskey-auth-" + "zzzCNTRL-supersecret123" },
			echoSub: "supersecret123",
		},
		{
			// Non-pattern-matching secret-ish value: the consumer shape
			// check fires and must not echo the value.
			name:    "consumer shape error with secret-ish value",
			mutate:  func(m *notifyv2.Message) { m.Consumer = "MY PASSWORD hunter22" },
			echoSub: "hunter22",
		},
		{
			name:    "pane shape error with free text",
			mutate:  func(m *notifyv2.Message) { m.Session.Pane = "pane says hunter22" },
			echoSub: "hunter22",
		},
		{
			name:    "host shape error with prose",
			mutate:  func(m *notifyv2.Message) { m.Host = "build failed near hunter22 line" },
			echoSub: "hunter22",
		},
		{
			name:    "deep_link parse error with token-ish path",
			mutate:  func(m *notifyv2.Message) { m.DeepLink = "abysslink://attach/%zz/notatoken99" },
			echoSub: "notatoken99",
		},
		{
			name:    "kind enum error with secret-ish value",
			mutate:  func(m *notifyv2.Message) { m.Kind = notifyv2.Kind("hunter22-kind") },
			echoSub: "hunter22",
		},
		{
			name:    "priority enum error with secret-ish value",
			mutate:  func(m *notifyv2.Message) { m.Priority = "hunter22" },
			echoSub: "hunter22",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := wellFormed()
			tc.mutate(&m)
			err := m.Validate()
			require.Error(t, err)
			assert.NotContains(t, err.Error(), tc.echoSub,
				"shape-check error must not echo the field value: %v", err)
		})
	}
}

// TestSecretPatterns_SingleSource asserts the conformance accessor exists and
// is non-empty — notifyv2 and the audit-log leak check share this one slice.
func TestSecretPatterns_SingleSource(t *testing.T) {
	pats := conformance.SecretPatterns()
	require.NotEmpty(t, pats)
	// The four canonical key[=:]value shapes and the bare provider-token
	// shapes must all be represented.
	joined := ""
	for _, p := range pats {
		joined += p.String() + "\n"
	}
	for _, want := range []string{
		"secret", "token", "password", "api",
		"tskey", "ghp", "github_pat", "AKIA", "xox",
	} {
		assert.Contains(t, joined, want)
	}
}

func TestNewMsgID(t *testing.T) {
	id := notifyv2.NewMsgID()
	_, err := ulid.ParseStrict(id)
	require.NoError(t, err, "NewMsgID must produce a strict-parseable ULID, got %q", id)
	assert.NotEqual(t, notifyv2.NewMsgID(), id, "two ULIDs must not collide")
}
