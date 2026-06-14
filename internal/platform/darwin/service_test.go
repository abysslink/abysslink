//go:build darwin

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

package darwin

import (
	"context"
	"errors"
	"testing"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServiceStatus covers the false-OK regression: shell.Runner reports a
// non-zero exit via Result.ExitCode with err == nil, so the old `if err != nil`
// check reported Running for a stopped/missing service. ServiceStatus must read
// the exit code AND require a live pid (loaded != running).
func TestServiceStatus(t *testing.T) {
	const label = "dev.abysslink.abysslinkd"

	tests := []struct {
		name    string
		result  shell.Result
		err     error
		want    platform.ServiceStatus
		wantErr bool
	}{
		{
			name:   "not bootstrapped (launchctl exit 113) is Stopped, not Running",
			result: shell.Result{ExitCode: 113, Stderr: `Could not find service "dev.abysslink.abysslinkd" in domain for user gui: 501`},
			want:   platform.ServiceStopped,
		},
		{
			name:   "loaded with a live pid is Running",
			result: shell.Result{ExitCode: 0, Stdout: "dev.abysslink.abysslinkd = {\n\tstate = running\n\tpid = 4242\n}\n"},
			want:   platform.ServiceRunning,
		},
		{
			name:   "loaded but no pid (waiting / crash-loop / missing binary) is Stopped",
			result: shell.Result{ExitCode: 0, Stdout: "dev.abysslink.abysslinkd = {\n\tstate = waiting\n}\n"},
			want:   platform.ServiceStopped,
		},
		{
			name:    "launchctl exec failure is Unknown (honest), with an error",
			err:     errors.New("exec: launchctl not found"),
			want:    platform.ServiceUnknown,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := shell.NewMockRunner(shell.Call{Result: tc.result, Err: tc.err})
			p := New(r)
			got, err := p.ServiceStatus(context.Background(), label)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLaunchdHasLivePID(t *testing.T) {
	assert.True(t, launchdHasLivePID("\tstate = running\n\tpid = 17\n"))
	assert.True(t, launchdHasLivePID("pid = 1"))
	assert.False(t, launchdHasLivePID("\tstate = waiting\n"))
	assert.False(t, launchdHasLivePID(""))
	// A "pid = " substring that is not the launchd field line must not match.
	assert.False(t, launchdHasLivePID("\tlast exit code = 0\n\tnocpid = 3\n"))
}
