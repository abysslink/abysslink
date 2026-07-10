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
	"errors"
	"os"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repairSpyModule is a minimal modules.Module double that records whether its
// Repair was invoked, so the tests can prove the lock gate refuses BEFORE any
// module bring-up runs (LOCK-REPAIR-01). Every other method is an inert no-op.
type repairSpyModule struct {
	name        string
	repairCalls int
}

func (m *repairSpyModule) Name() string                                         { return m.name }
func (m *repairSpyModule) Deps() []string                                       { return nil }
func (m *repairSpyModule) Detect(context.Context) ([]modules.Finding, error)    { return nil, nil }
func (m *repairSpyModule) Plan(context.Context, bool) ([]modules.Action, error) { return nil, nil }
func (m *repairSpyModule) Apply(context.Context) error                          { return nil }
func (m *repairSpyModule) Verify(context.Context) ([]modules.Finding, error)    { return nil, nil }
func (m *repairSpyModule) Repair(context.Context) error                         { m.repairCalls++; return nil }

// daemonReachableCall scripts the `tailscale status` probe (probeTailscaleDaemon)
// as "socket reachable" so requireTailscaleDaemon passes without starting a daemon.
func daemonReachableCall() shell.Call {
	return shell.Call{Result: shell.Result{ExitCode: 0}}
}

// TestRepairApply_LockOffRefusesBeforeAnyRepair proves that `abysslink repair
// --apply` runs the fail-closed Tailnet Lock gate BEFORE any module Repair — on
// a lock-off tailnet with no override flag, the tailscale/ssh bring-up must not
// run. Config `backend.type=headscale` must NOT make the gate skippable, because
// the tailscale module still shells `tailscale set --ssh` (LOCK-REPAIR-01).
func TestRepairApply_LockOffRefusesBeforeAnyRepair(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	spy := &repairSpyModule{name: "tailscale"}
	cfg := config.Defaults()
	cfg.Backend.Type = "headscale" // config says headscale — must NOT skip the live lock gate

	runner := shell.NewMockRunner(
		daemonReachableCall(), // Gate 1: tailscale status → daemon reachable
		lockStatusCall(false), // Gate 4: tailscale lock status --json → OFF
	)
	cc := &cmdContext{cfg: cfg, runner: runner, dryRun: false, apply: true, jsonOut: true}
	p := &testPrinter{out: &bytes.Buffer{}}

	// A bare command registers no override flags → all consent flags default to
	// false → fail-closed.
	repairErrs, gateErr := runRepairApply(context.Background(), &cobra.Command{}, p, cc,
		[]modules.Module{spy}, map[string]bool{"tailscale": true}, nil)

	require.Error(t, gateErr, "repair --apply must refuse when live Tailnet Lock is off")
	var ee *exitError
	require.True(t, errors.As(gateErr, &ee), "a fail-closed gate must return an exitError")
	assert.Equal(t, exitCodeFatal, ee.ExitCode(), "lock-off refusal is fail-closed (exit 2)")
	assert.Contains(t, gateErr.Error(), "--accept-lock-disabled",
		"the refusal must name the explicit audited override flag")
	assert.Nil(t, repairErrs, "no repair errors are collected when the gate blocks first")
	assert.Zero(t, spy.repairCalls, "no module Repair may run once the lock gate refuses")
	assert.NoFileExists(t, auditLogPathForTest(t),
		"a refusal (no override exercised) must not write a consent audit entry")
}

// TestRepairApply_LockOffWithOverrideProceedsAuditsAndRepairs proves that the
// audited override flag is honored on the repair --apply path exactly as on
// `up`: with --accept-lock-disabled, the gate proceeds, records the consent, and
// the module Repair runs. This is the un-skippable-but-overridable-with-audit
// half of the hard rule (LOCK-REPAIR-01).
func TestRepairApply_LockOffWithOverrideProceedsAuditsAndRepairs(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	spy := &repairSpyModule{name: "tailscale"}
	runner := shell.NewMockRunner(
		daemonReachableCall(), // Gate 1: tailscale status → reachable
		lockStatusCall(false), // Gate 4: lock OFF
	)
	cc := &cmdContext{cfg: config.Defaults(), runner: runner, dryRun: false, apply: true, jsonOut: true}
	p := &testPrinter{out: &bytes.Buffer{}}

	cmd := newRepairCmd() // registers --accept-lock-disabled
	require.NoError(t, cmd.Flags().Set("accept-lock-disabled", "true"))

	repairErrs, gateErr := runRepairApply(context.Background(), cmd, p, cc,
		[]modules.Module{spy}, map[string]bool{"tailscale": true}, nil)

	require.NoError(t, gateErr, "the audited override flag must let repair proceed past the lock gate")
	assert.Empty(t, repairErrs)
	assert.Equal(t, 1, spy.repairCalls, "the tailscale module Repair must run after the audited override")

	raw, err := os.ReadFile(auditLogPathForTest(t))
	require.NoError(t, err, "override must write a consent audit entry")
	assert.Contains(t, string(raw), "lock-override-consent", "audit op must be lock-override-consent")
	assert.Contains(t, string(raw), "tailnet-lock", "audit target must be tailnet-lock")
}

// TestRepairApply_DryRunSkipsGatesAndDoesNotRepair proves that dry-run repair
// stays side-effect free: no apply gate runs (the MockRunner is scripted with no
// calls, so any exec would fail the test) and no module Repair executes.
func TestRepairApply_DryRunSkipsGatesAndDoesNotRepair(t *testing.T) {
	spy := &repairSpyModule{name: "tailscale"}
	cc := &cmdContext{cfg: config.Defaults(), runner: shell.NewMockRunner(), dryRun: true, jsonOut: true}
	p := &testPrinter{out: &bytes.Buffer{}}

	repairErrs, gateErr := runRepairApply(context.Background(), &cobra.Command{}, p, cc,
		[]modules.Module{spy}, map[string]bool{"tailscale": true}, nil)

	require.NoError(t, gateErr, "dry-run must not run the apply gates")
	assert.Empty(t, repairErrs)
	assert.Zero(t, spy.repairCalls, "dry-run must not call Repair")
}

// TestRepairCmd_RegistersAuditedOverrideFlags is a drift guard: the repair
// command must expose the same audited override flags as `up`, so a lock-off
// rig can still be repaired with explicit, recorded consent (LOCK-REPAIR-01).
func TestRepairCmd_RegistersAuditedOverrideFlags(t *testing.T) {
	cmd := newRepairCmd()
	for _, name := range []string{"accept-lock-disabled", "force-unsafe", "accept-checkperiod-extension"} {
		assert.NotNil(t, cmd.Flags().Lookup(name), "repair must register the %q override flag", name)
	}
}
