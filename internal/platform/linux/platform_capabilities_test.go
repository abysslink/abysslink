//go:build linux

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

package linux

import (
	"context"
	"os"
	"testing"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privArgv prefixes sudo iff the test process is not root, mirroring
// runPrivileged so assertions hold whether CI runs as root or not.
func privArgv(name string, args ...string) []string {
	argv := append([]string{name}, args...)
	if os.Geteuid() != 0 {
		argv = append([]string{"sudo"}, argv...)
	}
	return argv
}

func rangeFirewall(t *testing.T, r shell.Runner) platform.RangeFirewall {
	t.Helper()
	p, err := New(r)
	require.NoError(t, err)
	fw, ok := p.Firewall().(platform.RangeFirewall)
	require.True(t, ok, "linux firewall must implement RangeFirewall")
	return fw
}

func TestLinuxFirewall_AllowPortRange_PrefersUFW(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{}) // ufw allow succeeds → no iptables fallback
	fw := rangeFirewall(t, r)

	require.NoError(t, fw.AllowPortRange(context.Background(), 60000, 61000, "udp"))
	assert.Equal(t, [][]string{privArgv("ufw", "allow", "60000:61000/udp")}, r.RunCalls())
}

func TestLinuxFirewall_AllowPortRange_FallsBackToIptables(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "ufw: command not found"}}, // ufw fails
		shell.Call{}, // iptables succeeds
	)
	fw := rangeFirewall(t, r)

	require.NoError(t, fw.AllowPortRange(context.Background(), 60000, 61000, "udp"))
	assert.Equal(t, [][]string{
		privArgv("ufw", "allow", "60000:61000/udp"),
		privArgv("iptables", "-A", "INPUT", "-p", "udp", "--dport", "60000:61000", "-j", "ACCEPT"),
	}, r.RunCalls())
}

func TestLinuxFirewall_RemovePortRange(t *testing.T) {
	// dry-run: reports, runs nothing.
	rDry := shell.NewMockRunner()
	got, err := rangeFirewall(t, rDry).RemovePortRange(context.Background(), 60000, 61000, "udp", true)
	require.NoError(t, err)
	assert.Equal(t, "host-firewall allow 60000:61000/udp", got)
	assert.Empty(t, rDry.RunCalls())

	// apply: ufw delete.
	rApply := shell.NewMockRunner(shell.Call{})
	_, err = rangeFirewall(t, rApply).RemovePortRange(context.Background(), 60000, 61000, "udp", false)
	require.NoError(t, err)
	assert.Equal(t, [][]string{privArgv("ufw", "delete", "allow", "60000:61000/udp")}, rApply.RunCalls())
}

func TestLinuxFirewall_IsPortRangeAllowed(t *testing.T) {
	tests := []struct {
		name string
		out  string
		code int
		want bool
	}{
		{"present", "To                         Action      From\n60000:61000/udp            ALLOW       Anywhere", 0, true},
		{"absent", "Status: active\n22/tcp ALLOW Anywhere", 0, false},
		{"ufw-error", "", 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: tc.out, ExitCode: tc.code}})
			fw := rangeFirewall(t, r)
			got, err := fw.IsPortRangeAllowed(context.Background(), 60000, 61000, "udp")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
