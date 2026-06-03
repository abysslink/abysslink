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

package tailscale

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
)

func newTestModule(calls ...shell.Call) *Module {
	cfg := config.Defaults()
	cfg.Tailnet.SSH = true
	return New(modules.Deps{Runner: shell.NewMockRunner(calls...), Cfg: cfg})
}

func TestFunnelActive(t *testing.T) {
	cases := []struct {
		name string
		res  shell.Result
		err  bool
		want bool
	}{
		{"active", shell.Result{Stdout: "https://rig.tail-scale.ts.net (Funnel on)\n|-- / proxy http://127.0.0.1:3000", ExitCode: 0}, false, true},
		{"not configured", shell.Result{Stdout: "Funnel is not configured.", ExitCode: 0}, false, false},
		{"command unavailable", shell.Result{ExitCode: 1}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModule(shell.Call{Result: tc.res})
			assert.Equal(t, tc.want, m.funnelActive(context.Background()))
		})
	}
}

func TestServeActive(t *testing.T) {
	cases := []struct {
		name string
		res  shell.Result
		want bool
	}{
		{"active proxy", shell.Result{Stdout: "https://rig.ts.net\n|-- /  proxy http://127.0.0.1:8080", ExitCode: 0}, true},
		{"no config", shell.Result{Stdout: "No serve config", ExitCode: 0}, false},
		{"empty", shell.Result{Stdout: "", ExitCode: 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModule(shell.Call{Result: tc.res})
			assert.Equal(t, tc.want, m.serveActive(context.Background()))
		})
	}
}

func TestFunnelOK(t *testing.T) {
	// Clean path: neither funnel nor serve is active → expect SeverityOK finding
	// with Check=="funnel".
	m := newTestModule(
		// funnelActive call: "Funnel is not configured."
		shell.Call{Result: shell.Result{Stdout: "Funnel is not configured.", ExitCode: 0}},
		// serveActive call: no serve config
		shell.Call{Result: shell.Result{Stdout: "No serve config", ExitCode: 0}},
	)
	findings := m.checkNoPublicExposure(context.Background())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "funnel" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"funnel\" on clean path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "clean path must emit SeverityOK for funnel")
}

func TestSSHFindings(t *testing.T) {
	m := newTestModule()

	// SSH disabled in config → no finding.
	mDisabled := New(modules.Deps{Cfg: config.Defaults()})
	mDisabled.cfg.Tailnet.SSH = false
	assert.Empty(t, mDisabled.sshFindings(&tailscaleStatus{}, false))

	// Sandboxed GUI build → ssh_sandboxed.
	got := m.sshFindings(&tailscaleStatus{}, true)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "ssh_sandboxed", got[0].Check)
	}

	// SSH already enabled (TailscaleSSH true) → no finding.
	assert.Empty(t, m.sshFindings(&tailscaleStatus{TailscaleSSH: true}, false))

	// SSH capability present → no finding.
	st := &tailscaleStatus{}
	st.Self.Capabilities = []string{"https://tailscale.com/cap/ssh"}
	assert.Empty(t, m.sshFindings(st, false))

	// SSH wanted but absent → ssh finding.
	got = m.sshFindings(&tailscaleStatus{}, false)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "ssh", got[0].Check)
		assert.Equal(t, modules.SeverityWarning, got[0].Severity)
	}
}
