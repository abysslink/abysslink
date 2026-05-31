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

package backend

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
)

// TestCheckHsProcUserLinux_RootIsFatal covers the CR-02 security-gate branch
// directly: systemd reports an empty "User=" for a service with no User=
// directive, which means the service runs as root. The check MUST treat
// "", "root", and "0" as DoctorFatal. The full-suite tests only exercise the
// "User=headscale" OK path, so this is the only coverage of the dangerous case.
func TestCheckHsProcUserLinux_RootIsFatal(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   DoctorSeverity
	}{
		{"empty User= means root", "User=\n", DoctorFatal},
		{"explicit root", "User=root\n", DoctorFatal},
		{"numeric uid 0", "User=0\n", DoctorFatal},
		{"dedicated headscale user", "User=headscale\n", DoctorOK},
		{"some other non-root user", "User=nobody\n", DoctorWarning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := shell.NewMockRunner(
				shell.Call{Result: shell.Result{Stdout: tt.stdout, ExitCode: 0}},
			)
			f := checkHsProcUserLinux(context.Background(), runner, "hs-proc-user", "headscale")
			assert.Equal(t, tt.want, f.Severity,
				"checkHsProcUserLinux(%q) severity", tt.stdout)
		})
	}
}

// TestCheckHsProcUserLinux_QueryFailureIsWarning asserts that an inability to
// query systemd (exec error or non-zero exit) is a warning, not a false PASS.
func TestCheckHsProcUserLinux_QueryFailureIsWarning(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 1}},
	)
	f := checkHsProcUserLinux(context.Background(), runner, "hs-proc-user", "headscale")
	assert.Equal(t, DoctorWarning, f.Severity)
}

// TestCheckHsProcUserMac_RootIsFatal asserts the macOS path flags a non-_headscale
// running user (e.g. root) as DoctorFatal, and _headscale as DoctorOK.
func TestCheckHsProcUserMac_RootIsFatal(t *testing.T) {
	tests := []struct {
		name   string
		psUser string
		want   DoctorSeverity
	}{
		{"running as root", "root\n", DoctorFatal},
		{"running as _headscale", "_headscale\n", DoctorOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := shell.NewMockRunner(
				shell.Call{Result: shell.Result{Stdout: "123\t0\tnet.abysslink.headscale\n", ExitCode: 0}},
				shell.Call{Result: shell.Result{Stdout: tt.psUser, ExitCode: 0}},
			)
			f := checkHsProcUserMac(context.Background(), runner, "hs-proc-user", "headscale")
			assert.Equal(t, tt.want, f.Severity,
				"checkHsProcUserMac(ps user=%q) severity", tt.psUser)
		})
	}
}
