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

// Tests for private (unexported) helpers in netbird_doctor.go.
// This file uses package backend (not backend_test) to access unexported symbols.
package backend

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
)

// ── parseNetBirdVersion tests ─────────────────────────────────────────────────

// TestParseNetBirdVersion covers various --version output formats from the
// netbird-server binary.
func TestParseNetBirdVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantVer string
		wantOK  bool
	}{
		{
			name:    "standard format",
			input:   "netbird-server version v0.71.4\n",
			wantVer: "0.71.4",
			wantOK:  true,
		},
		{
			name:    "bare version",
			input:   "v0.57.0",
			wantVer: "0.57.0",
			wantOK:  true,
		},
		{
			name:    "version with pre-release",
			input:   "netbird-server version v0.71.4-rc1",
			wantVer: "0.71.4-rc1",
			wantOK:  true,
		},
		{
			name:    "empty output",
			input:   "",
			wantVer: "",
			wantOK:  false,
		},
		{
			name:    "no version in output",
			input:   "error: cannot load config",
			wantVer: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, ok := parseNetBirdVersion(tt.input)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch")
			assert.Equal(t, tt.wantVer, ver, "version mismatch")
		})
	}
}

// ── semverLessThan tests ──────────────────────────────────────────────────────

// TestSemverLessThan covers the semver comparison helper used by nb-version.
func TestSemverLessThan(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"below floor", "0.30.0", "0.57.0", true},
		{"at floor", "0.57.0", "0.57.0", false},
		{"above floor", "0.71.4", "0.57.0", false},
		{"major version difference", "1.0.0", "0.57.0", false},
		{"minor version boundary", "0.56.9", "0.57.0", true},
		{"patch version boundary", "0.57.0", "0.57.1", true},
		{"v-prefix stripped", "v0.71.4", "v0.57.0", false},
		{"equal versions", "0.71.4", "0.71.4", false},
		{"zero vs nonzero", "0.0.0", "0.57.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := semverLessThan(tt.a, tt.b)
			assert.Equal(t, tt.want, got, "semverLessThan(%q, %q)", tt.a, tt.b)
		})
	}
}

// ── checkNbProcUserLinux internal tests ──────────────────────────────────────

// TestCheckNbProcUserLinux_RootIsFatal covers the security-critical branch
// where systemd reports root user. Must FAIL for "", "root", "0".
func TestCheckNbProcUserLinux_RootIsFatal(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   DoctorSeverity
	}{
		{"empty User= means root", "User=\n", DoctorFatal},
		{"explicit root", "User=root\n", DoctorFatal},
		{"numeric uid 0", "User=0\n", DoctorFatal},
		{"netbird-server user", "User=netbird-server\n", DoctorOK},
		{"other non-root user", "User=nobody\n", DoctorOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := shell.NewMockRunner(
				shell.Call{Result: shell.Result{Stdout: tt.stdout, ExitCode: 0}},
			)
			f := checkNbProcUserLinux(context.Background(), runner, "nb-proc-user", "netbird")
			assert.Equal(t, tt.want, f.Severity,
				"checkNbProcUserLinux(%q) severity", tt.stdout)
		})
	}
}

// TestCheckNbProcUserLinux_QueryFailureIsWarning asserts that failure to query
// systemd is a warning (service may not be installed), not a false PASS.
func TestCheckNbProcUserLinux_QueryFailureIsWarning(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 1}},
	)
	f := checkNbProcUserLinux(context.Background(), runner, "nb-proc-user", "netbird")
	assert.Equal(t, DoctorWarning, f.Severity)
}

// ── extractIssuerBase tests ───────────────────────────────────────────────────

// TestExtractIssuerBase verifies that ZITADEL issuer URLs are correctly reduced
// to the base URL for the management API probe.
func TestExtractIssuerBase(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{
			name:   "plain domain issuer",
			issuer: "https://zitadel.example.com",
			want:   "https://zitadel.example.com",
		},
		{
			name:   "issuer with path",
			issuer: "https://zitadel.example.com/realms/netbird",
			want:   "https://zitadel.example.com",
		},
		{
			name:   "issuer with trailing slash",
			issuer: "https://zitadel.example.com/",
			want:   "https://zitadel.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIssuerBase(tt.issuer)
			assert.Equal(t, tt.want, got)
		})
	}
}
