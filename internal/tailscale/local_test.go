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

package tailscale_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tailscale"
)

const runningStatusJSON = `{
	"BackendState": "Running",
	"Self": {
		"HostName": "my-laptop",
		"DNSName": "my-laptop.example.ts.net.",
		"TailscaleIPs": ["100.64.0.1", "fd7a:115c::1"],
		"Online": true
	},
	"Health": [],
	"MagicDNSSuffix": "example.ts.net",
	"CurrentTailnet": {
		"Name": "example.com",
		"MagicDNSSuffix": "example.ts.net"
	}
}`

const needsLoginStatusJSON = `{
	"BackendState": "NeedsLogin",
	"Self": null,
	"Health": ["not logged in"],
	"MagicDNSSuffix": "",
	"CurrentTailnet": null
}`

func TestStatus_Running(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: runningStatusJSON, ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	st, err := client.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, tailscale.StateRunning, st.BackendState)
	assert.NotNil(t, st.Self)
	assert.Equal(t, "my-laptop", st.Self.HostName)
	assert.Equal(t, "my-laptop.example.ts.net.", st.Self.DNSName)
	assert.True(t, st.Self.Online)
	assert.Len(t, st.Self.TailscaleIPs, 2)
	assert.Equal(t, "100.64.0.1", st.Self.TailscaleIPs[0].String())
	assert.Equal(t, "example.ts.net", st.MagicDNSSuffix)
	assert.NotNil(t, st.CurrentTailnet)
	assert.Equal(t, "example.com", st.CurrentTailnet.Name)
	assert.True(t, runner.Done())
}

func TestStatus_NeedsLogin(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: needsLoginStatusJSON, ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	st, err := client.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, tailscale.StateNeedsLogin, st.BackendState)
	assert.Nil(t, st.Self)
	assert.Contains(t, st.Health, "not logged in")
	assert.True(t, runner.Done())
}

func TestStatus_Error(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stderr: "connection refused", ExitCode: 1},
	})
	client := tailscale.NewLocalClient(runner)

	_, err := client.Status(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exited 1")
}

func TestIP(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: runningStatusJSON, ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	ip, err := client.IP(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.1", ip)
	assert.True(t, runner.Done())
}

func TestIP_NeedsLogin(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: needsLoginStatusJSON, ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	ip, err := client.IP(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "", ip)
}

func TestHostname(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: runningStatusJSON, ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	hn, err := client.Hostname(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "my-laptop", hn)
	assert.True(t, runner.Done())
}

func TestLock(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: `{"Enabled": true}`, ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	ls, err := client.Lock(context.Background())
	require.NoError(t, err)
	assert.True(t, ls.Enabled)
	assert.True(t, runner.Done())
}

func TestLock_Disabled(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: `{"Enabled": false}`, ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	ls, err := client.Lock(context.Background())
	require.NoError(t, err)
	assert.False(t, ls.Enabled)
}

func TestUp(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	err := client.Up(context.Background(), tailscale.UpOpts{
		Hostname: "test-host",
		SSH:      true,
	})
	require.NoError(t, err)
	assert.True(t, runner.Done())

	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "tailscale", calls[0].Name)
	// args should include up, --hostname=test-host, --ssh, --accept-routes=false
	assert.Contains(t, calls[0].Args, "up")
	assert.Contains(t, calls[0].Args, "--hostname=test-host")
	assert.Contains(t, calls[0].Args, "--ssh")
	assert.Contains(t, calls[0].Args, "--accept-routes=false")
}

func TestUp_AdvertiseExitNode(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	err := client.Up(context.Background(), tailscale.UpOpts{
		AdvertiseExitNode: true,
		AcceptRoutes:      true,
	})
	require.NoError(t, err)
	calls := runner.RecordedCalls()
	assert.Contains(t, calls[0].Args, "--advertise-exit-node")
	// when AcceptRoutes=true, --accept-routes=false should NOT be in args
	assert.NotContains(t, calls[0].Args, "--accept-routes=false")
}

func TestDown(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	err := client.Down(context.Background())
	require.NoError(t, err)
	assert.True(t, runner.Done())

	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "tailscale", calls[0].Name)
	assert.Contains(t, calls[0].Args, "down")
}

func TestSet(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 0},
	})
	client := tailscale.NewLocalClient(runner)

	err := client.Set(context.Background(), tailscale.SetOpts{
		Hostname:   "new-name",
		AutoUpdate: true,
	})
	require.NoError(t, err)
	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].Args, "--hostname=new-name")
	assert.Contains(t, calls[0].Args, "--auto-update")
}
