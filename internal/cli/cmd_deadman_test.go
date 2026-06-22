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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
)

// writeDeadmanCfg writes a valid config (optionally with the dead-man switch
// pre-enabled) and returns its path. It also points XDG_STATE_HOME at a temp dir
// so the audit log + deadman state files land under the test sandbox.
func writeDeadmanCfg(t *testing.T, enabled bool, intervalHours int) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	cfg.Deadman = config.DeadmanConfig{Enabled: enabled, IntervalHours: intervalHours}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// runDeadmanCLI executes `abysslink deadman <args...>` against a fresh root and
// returns combined output + the error.
func runDeadmanCLI(t *testing.T, cfgPath string, args ...string) (string, error) {
	t.Helper()
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	full := append([]string{"deadman"}, args...)
	full = append(full, "--config", cfgPath)
	root.SetArgs(full)
	err := root.Execute()
	return out.String(), err
}

// TestDeadmanEnable_DryRunDefault asserts `deadman enable` without --apply
// prints a plan and does NOT persist (Enabled stays false on disk).
func TestDeadmanEnable_DryRunDefault(t *testing.T) {
	cfgPath := writeDeadmanCfg(t, false, 0)

	out, err := runDeadmanCLI(t, cfgPath, "enable")
	require.NoError(t, err)
	assert.Contains(t, out, "[plan]")
	assert.Contains(t, out, "--apply")

	// On-disk config must remain disabled (dry-run wrote nothing).
	cfg, lErr := config.Load(cfgPath)
	require.NoError(t, lErr)
	assert.False(t, cfg.Deadman.Enabled, "dry-run must NOT persist the enable")
}

// TestDeadmanEnable_ApplyPersists asserts `deadman enable --apply` sets
// Enabled=true in the written config, and --interval-hours is honoured.
func TestDeadmanEnable_ApplyPersists(t *testing.T) {
	cfgPath := writeDeadmanCfg(t, false, 0)

	out, err := runDeadmanCLI(t, cfgPath, "enable", "--interval-hours", "12", "--apply")
	require.NoError(t, err)
	assert.Contains(t, out, "12h")

	cfg, lErr := config.Load(cfgPath)
	require.NoError(t, lErr)
	assert.True(t, cfg.Deadman.Enabled, "--apply must persist Enabled=true")
	assert.Equal(t, 12, cfg.Deadman.IntervalHours)
}

// TestDeadmanEnable_ApplySeedsContact is the CR-02 regression at the CLI layer:
// `deadman enable --apply` must seed the contact clock (deadman-contact.json)
// so the no-contact timer counts from enable. A dry-run enable seeds NOTHING.
// A second enable must NOT overwrite the existing contact (idempotent — a
// re-enable preserves an in-flight deadline).
func TestDeadmanEnable_ApplySeedsContact(t *testing.T) {
	cfgPath := writeDeadmanCfg(t, false, 0)

	// The CLI resolves the contact path under XDG_STATE_HOME (set by writeDeadmanCfg).
	contactPath, pErr := deadmanContactPathFn()
	require.NoError(t, pErr)

	// Dry-run enable seeds nothing.
	_, dErr := runDeadmanCLI(t, cfgPath, "enable")
	require.NoError(t, dErr)
	_, foundDry, lErr0 := deadman.LastContact(contactPath, time.Now)
	require.NoError(t, lErr0)
	assert.False(t, foundDry, "dry-run enable must NOT seed the contact clock")

	// --apply enable seeds the contact clock.
	_, aErr := runDeadmanCLI(t, cfgPath, "enable", "--apply")
	require.NoError(t, aErr)
	firstContact, found, lErr := deadman.LastContact(contactPath, time.Now)
	require.NoError(t, lErr)
	assert.True(t, found, "deadman enable --apply must seed the contact clock (CR-02 fail-open fix)")

	// A second enable must NOT overwrite the existing contact (idempotent).
	_, a2Err := runDeadmanCLI(t, cfgPath, "enable", "--apply")
	require.NoError(t, a2Err)
	secondContact, found2, lErr2 := deadman.LastContact(contactPath, time.Now)
	require.NoError(t, lErr2)
	assert.True(t, found2)
	assert.Equal(t, firstContact, secondContact, "a second enable must NOT reset the seeded contact")
}

// TestDeadmanEnable_RejectsSubFloor asserts a sub-floor --interval-hours is
// rejected before any write (config.Validate gate).
func TestDeadmanEnable_RejectsSubFloor(t *testing.T) {
	cfgPath := writeDeadmanCfg(t, false, 0)

	_, err := runDeadmanCLI(t, cfgPath, "enable", "--interval-hours", "-5", "--apply")
	require.Error(t, err, "a sub-floor interval must be rejected")

	cfg, lErr := config.Load(cfgPath)
	require.NoError(t, lErr)
	assert.False(t, cfg.Deadman.Enabled, "a rejected enable must not persist")
}

// TestDeadmanHeartbeatThenStatus asserts a heartbeat writes the last-contact
// timestamp and status afterward reports a fresh contact + the full remaining
// interval, without mutating config.
func TestDeadmanHeartbeatThenStatus(t *testing.T) {
	cfgPath := writeDeadmanCfg(t, true, 24)

	// Status before any heartbeat: enabled, no persisted contact yet.
	out, err := runDeadmanCLI(t, cfgPath, "status")
	require.NoError(t, err)
	assert.Contains(t, out, "enabled")
	assert.Contains(t, out, "true")

	// Heartbeat records the contact (audit-written).
	hbOut, hbErr := runDeadmanCLI(t, cfgPath, "heartbeat")
	require.NoError(t, hbErr)
	assert.Contains(t, hbOut, "Heartbeat recorded")

	// Status after the heartbeat: a fresh last_contact and ~full remaining.
	stOut, stErr := runDeadmanCLI(t, cfgPath, "status")
	require.NoError(t, stErr)
	assert.Contains(t, stOut, "last_contact")
	assert.Contains(t, stOut, "remaining")
	// Remaining should be at/near the full 24h interval right after a heartbeat
	// (24h0m0s when the round lands exactly on now, or 23hXX otherwise).
	assert.True(t, strings.Contains(stOut, "24h") || strings.Contains(stOut, "23h"),
		"remaining should be near the full interval after a heartbeat, got: %s", stOut)
}

// TestDeadmanStatus_Disabled asserts status on a disabled switch reports
// enabled=false and mutates nothing.
func TestDeadmanStatus_Disabled(t *testing.T) {
	cfgPath := writeDeadmanCfg(t, false, 0)

	out, err := runDeadmanCLI(t, cfgPath, "status")
	require.NoError(t, err)
	assert.Contains(t, out, "enabled")
	assert.Contains(t, out, "false")

	cfg, lErr := config.Load(cfgPath)
	require.NoError(t, lErr)
	assert.False(t, cfg.Deadman.Enabled)
}

// TestDeadmanRegisteredOnRoot asserts newDeadmanCmd is wired onto the root
// command (discoverable as `abysslink deadman`).
func TestDeadmanRegisteredOnRoot(t *testing.T) {
	root := buildRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "deadman" {
			found = true
			// Subcommands present.
			subs := map[string]bool{}
			for _, s := range c.Commands() {
				subs[s.Name()] = true
			}
			assert.True(t, subs["enable"], "deadman enable subcommand")
			assert.True(t, subs["status"], "deadman status subcommand")
			assert.True(t, subs["heartbeat"], "deadman heartbeat subcommand")
		}
	}
	assert.True(t, found, "deadman command must be registered on root")
}
