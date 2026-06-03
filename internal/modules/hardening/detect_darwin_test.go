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

//go:build darwin

package hardening

import (
	"context"
	"fmt"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckFileVault_FatalWhenOff(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "FileVault is Off.\n"}})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "filevault", findings[0].Check)
	assert.Equal(t, modules.SeverityFatal, findings[0].Severity)
}

// TestCheckFileVault_OKWhenOn asserts checkFileVault returns a SeverityOK finding
// when FileVault is fully enabled (DOC-01 backfill).
func TestCheckFileVault_OKWhenOn(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "FileVault is On.\n"}})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "should return a SeverityOK finding when FileVault is On")
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "filevault" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityOK, found.Severity)
}

// TestCheckFileVault_FatalWhenEncryptionInProgress asserts checkFileVault returns
// FATAL when FileVault encryption is in progress (not fully enabled, DOC-02).
func TestCheckFileVault_FatalWhenEncryptionInProgress(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "Encryption in progress: Percent completed = 42\n"}})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "filevault" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityFatal, found.Severity)
}

// TestCheckFileVault_FatalWhenDeferredEnablement asserts checkFileVault returns
// FATAL when FileVault deferred enablement is active (not fully enabled, DOC-02).
func TestCheckFileVault_FatalWhenDeferredEnablement(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "Deferred enablement appears to be active for 'alice'\n"}})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "filevault" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityFatal, found.Severity)
}

// TestCheckFileVault_FatalWhenDecryptionInProgress asserts checkFileVault returns
// FATAL when FileVault decryption is in progress (not fully enabled, DOC-02).
func TestCheckFileVault_FatalWhenDecryptionInProgress(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "Decryption in progress: Percent completed = 17\n"}})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "filevault" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityFatal, found.Severity)
}

// TestCheckFileVault_FatalOnExecError asserts checkFileVault returns FATAL (not
// an error return) when fdesetup fails to execute (DOC-02 / D-06).
func TestCheckFileVault_FatalOnExecError(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Err: fmt.Errorf("exec: fdesetup not found")})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err, "exec error must become a FATAL finding, not an error return")
	require.NotEmpty(t, findings)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "filevault" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "disk-encryption state is UNKNOWN")
}

func TestCheckFirewall_WarnWhenDisabled(t *testing.T) {
	json := `{"SPFirewallDataType":[{"spfw_global_state":"disabled"}]}`
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: json}})
	m := &Module{runner: r}
	findings, err := checkFirewall(context.Background(), m)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "firewall", findings[0].Check)
}

func TestCheckFirewall_NilWhenEnabled(t *testing.T) {
	json := `{"SPFirewallDataType":[{"spfw_global_state":"enabled"}]}`
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: json}})
	m := &Module{runner: r}
	findings, err := checkFirewall(context.Background(), m)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
