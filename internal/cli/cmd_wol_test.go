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

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// writeWolCfg writes a config with a single rig (optionally carrying mac) and
// returns the config path.
func writeWolCfg(t *testing.T, rigName, mac string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	cfg.Modules.Upsnap.Enabled = true
	cfg.Rigs = []config.RigConfig{
		{Name: rigName, Hostname: rigName + ".ts.net", Backend: "tailscale", MAC: mac},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// wolHarness installs counting seams for the UDP send and audit append, and
// restores the originals on cleanup. It returns pointers to the two counters.
func wolHarness(t *testing.T) (sends, audits *int64) {
	t.Helper()
	var sendN, auditN int64

	origSend := wolSendFunc
	origAudit := wolAuditFunc
	wolSendFunc = func(_ context.Context, _ shell.Runner, _ []byte) error {
		atomic.AddInt64(&sendN, 1)
		return nil
	}
	wolAuditFunc = func(_ context.Context, _ *cmdContext, _ string, _ string) error {
		atomic.AddInt64(&auditN, 1)
		return nil
	}
	t.Cleanup(func() {
		wolSendFunc = origSend
		wolAuditFunc = origAudit
	})
	return &sendN, &auditN
}

// runWol executes the wol command via the real root command tree.
func runWol(t *testing.T, cfgPath string, args ...string) (string, error) {
	t.Helper()
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	full := append([]string{"wol", "--config", cfgPath}, args...)
	root.SetArgs(full)
	err := root.Execute()
	return out.String(), err
}

// TestWolCmd_DryRun_SendsZeroPackets is the HARD FLOOR (T-21-01-01): without
// --apply, zero UDP packets are sent and zero audit entries are written.
func TestWolCmd_DryRun_SendsZeroPackets(t *testing.T) {
	sends, audits := wolHarness(t)
	cfgPath := writeWolCfg(t, "laptop", "aa:bb:cc:dd:ee:ff")

	out, err := runWol(t, cfgPath, "laptop")
	require.NoError(t, err)
	assert.Equal(t, int64(0), atomic.LoadInt64(sends), "dry-run must send ZERO UDP packets")
	assert.Equal(t, int64(0), atomic.LoadInt64(audits), "dry-run must write ZERO audit entries")
	assert.Contains(t, out, "DRY RUN: would send WoL magic packet")
	assert.Contains(t, out, "laptop")
}

// TestWolCmd_DryRun_PrintsSummary verifies the dry-run summary is printed via
// the Printer (not fmt.Println).
func TestWolCmd_DryRun_PrintsSummary(t *testing.T) {
	wolHarness(t)
	cfgPath := writeWolCfg(t, "laptop", "aa:bb:cc:dd:ee:ff")

	out, err := runWol(t, cfgPath, "laptop")
	require.NoError(t, err)
	assert.Contains(t, out, "DRY RUN: would send WoL magic packet to laptop")
	assert.Contains(t, out, "aa:bb:cc:dd:ee:ff")
}

// TestWolCmd_Apply_AuditsEntry verifies --apply writes exactly one audit entry
// and sends exactly one packet.
func TestWolCmd_Apply_AuditsEntry(t *testing.T) {
	sends, audits := wolHarness(t)
	cfgPath := writeWolCfg(t, "laptop", "aa:bb:cc:dd:ee:ff")

	out, err := runWol(t, cfgPath, "laptop", "--apply")
	require.NoError(t, err)
	assert.Equal(t, int64(1), atomic.LoadInt64(audits), "--apply must write exactly one audit entry")
	assert.Equal(t, int64(1), atomic.LoadInt64(sends), "--apply must send exactly one packet")
	assert.Contains(t, out, "Sent WoL magic packet to laptop")
}

// TestWolCmd_Apply_AuditOrderBeforeSend verifies the audit append happens
// before the UDP send (audit-then-act): if the audit fails, no packet is sent.
func TestWolCmd_Apply_AuditFailsNoSend(t *testing.T) {
	var sendN int64
	origSend := wolSendFunc
	origAudit := wolAuditFunc
	wolSendFunc = func(_ context.Context, _ shell.Runner, _ []byte) error {
		atomic.AddInt64(&sendN, 1)
		return nil
	}
	wolAuditFunc = func(_ context.Context, _ *cmdContext, _ string, _ string) error {
		return assert.AnError
	}
	t.Cleanup(func() {
		wolSendFunc = origSend
		wolAuditFunc = origAudit
	})

	cfgPath := writeWolCfg(t, "laptop", "aa:bb:cc:dd:ee:ff")
	_, err := runWol(t, cfgPath, "laptop", "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit")
	assert.Equal(t, int64(0), atomic.LoadInt64(&sendN), "no packet may be sent if audit fails")
}

// TestWolCmd_MissingMAC verifies a rig with no mac: field returns an error.
func TestWolCmd_MissingMAC(t *testing.T) {
	wolHarness(t)
	cfgPath := writeWolCfg(t, "laptop", "")

	_, err := runWol(t, cfgPath, "laptop", "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no mac address configured")
}

// TestWolCmd_InvalidMAC verifies a malformed mac: returns an error and sends
// nothing.
func TestWolCmd_InvalidMAC(t *testing.T) {
	sends, _ := wolHarness(t)
	cfgPath := writeWolCfg(t, "laptop", "not-a-mac")

	_, err := runWol(t, cfgPath, "laptop", "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MAC address")
	assert.Equal(t, int64(0), atomic.LoadInt64(sends), "invalid MAC must not send")
}

// TestWolCmd_UnknownRig verifies an unknown rig name returns an error.
func TestWolCmd_UnknownRig(t *testing.T) {
	wolHarness(t)
	cfgPath := writeWolCfg(t, "laptop", "aa:bb:cc:dd:ee:ff")

	_, err := runWol(t, cfgPath, "desktop", "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
