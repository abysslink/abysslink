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
		{"consumer uppercase and space", mut(func(m *notifyv2.Message) { m.Consumer = "Claude Code" }), "consumer"},
		{"session id wrong shape", mut(func(m *notifyv2.Message) { m.Session.Session = "$x" }), "session"},
		{"window id missing @", mut(func(m *notifyv2.Message) { m.Session.Window = "5" }), "window"},
		{"pane id missing percent", mut(func(m *notifyv2.Message) { m.Session.Pane = "3" }), "pane"},
		{"deep_link https scheme", mut(func(m *notifyv2.Message) { m.DeepLink = "https://evil.example/attach" }), "deep_link"},
		{"fetch url http scheme", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "http://100.110.12.7/content/x", TTLSeconds: 60}
		}), "fetch"},
		{"fetch host off tailnet", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "https://example.com/content/x", TTLSeconds: 60}
		}), "fetch"},
		{"fetch ttl zero", mut(func(m *notifyv2.Message) {
			m.Fetch = &notifyv2.FetchRef{URLTailnet: "https://100.110.12.7/content/x", TTLSeconds: 0}
		}), "fetch"},
		{"priority urgent not allowed on wire", mut(func(m *notifyv2.Message) { m.Priority = "urgent" }), "priority"},
		{"unknown action id", mut(func(m *notifyv2.Message) { m.Actions = []notifyv2.Action{{ID: "reboot"}} }), "action"},
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
	for _, l := range strings.Split(string(data), "\n") {
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

// TestSecretPatterns_SingleSource asserts the conformance accessor exists and
// is non-empty — notifyv2 and the audit-log leak check share this one slice.
func TestSecretPatterns_SingleSource(t *testing.T) {
	pats := conformance.SecretPatterns()
	require.NotEmpty(t, pats)
	// The four canonical shapes must be represented.
	joined := ""
	for _, p := range pats {
		joined += p.String() + "\n"
	}
	for _, want := range []string{"secret", "token", "password", "api"} {
		assert.Contains(t, joined, want)
	}
}

func TestNewMsgID(t *testing.T) {
	id := notifyv2.NewMsgID()
	_, err := ulid.ParseStrict(id)
	require.NoError(t, err, "NewMsgID must produce a strict-parseable ULID, got %q", id)
	assert.NotEqual(t, notifyv2.NewMsgID(), id, "two ULIDs must not collide")
}
