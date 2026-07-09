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

package quorum

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFloorProbes_AllDeny: every shipped floor probe fixture must DENY with
// its own rule code (the runtime doctor sec-quorum-floor contract).
func TestFloorProbes_AllDeny(t *testing.T) {
	e := New(Config{}, WithLogger(discardLogger()))
	for _, probe := range FloorProbes() {
		d, err := e.Evaluate(context.Background(), probe.Name, probe.Args)
		require.NoError(t, err, "probe %s", probe.Rule)
		assert.Equal(t, OutcomeDeny, d.Outcome, "floor probe %s must DENY", probe.Rule)
		assert.Equal(t, probe.Rule, d.FloorRule, "floor probe %s must match its own rule", probe.Rule)
	}
}

// TestGarbageConsensus_FloorStillDenies is the wrong-consensus property test:
// all four verifiers stubbed to confident ALLOW over EVERY floor action must
// still DENY — unanimous verifier agreement cannot approve a deny-floor
// action (verifier-collusion / garbage-consensus case).
func TestGarbageConsensus_FloorStillDenies(t *testing.T) {
	stubs := fourStubs([4]Vote{allowHigh(""), allowHigh(""), allowHigh(""), allowHigh("")})
	e := newStubEngine(t, stubs...)
	for _, probe := range FloorProbes() {
		d, err := e.Evaluate(context.Background(), probe.Name, probe.Args)
		require.NoError(t, err, "probe %s", probe.Rule)
		assert.Equal(t, OutcomeDeny, d.Outcome,
			"floor action %s must DENY even under unanimous ALLOW@High consensus", probe.Rule)
		assert.Empty(t, d.Votes, "the stage-0 floor must fire BEFORE any verifier runs")
	}
}

// TestTripwire_CanaryMarkerDenies: the compiled canary marker and config-added
// markers instant-DENY, emit the quorum-tripwire audit op, and alert.
func TestTripwire_CanaryMarkerDenies(t *testing.T) {
	app := &fakeAppender{}
	alerts := 0
	e := New(Config{CanaryMarkers: []string{"extra-canary-marker"}},
		WithLogger(discardLogger()),
		WithAuditAppender(app),
		WithAlertFunc(func(context.Context, string, string) { alerts++ }))

	t.Run("compiled default marker", func(t *testing.T) {
		d, err := e.Evaluate(context.Background(), "cat", []string{"/notes/" + DefaultCanaryMarker + ".txt"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeDeny, d.Outcome)
		assert.Equal(t, "canary-tripwire", d.FloorRule)
		assert.Equal(t, "default", d.TripwireMarker)
	})

	t.Run("config-added marker (add-only)", func(t *testing.T) {
		d, err := e.Evaluate(context.Background(), "ls", []string{"extra-canary-marker"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeDeny, d.Outcome)
		assert.Equal(t, "canary_paths", d.TripwireMarker, "the marker label, never the raw token")
	})

	// Two tripwire ops + two decision ops must be on the audit chain.
	var tripwires, decisions int
	for _, en := range app.all() {
		switch en.op {
		case "quorum-tripwire":
			tripwires++
		case "quorum-decision":
			decisions++
		}
	}
	assert.Equal(t, 2, tripwires, "every tripwire hit must append a quorum-tripwire entry")
	assert.Equal(t, 2, decisions, "every evaluation must append a quorum-decision entry")
	assert.Equal(t, 2, alerts, "every tripwire/floor deny must dispatch an alert")
}

// TestFloor_AuditLogDestruction covers the audit-log-destruction rule shapes:
// direct deletion, parent-directory deletion, and dd targeting the log.
func TestFloor_AuditLogDestruction(t *testing.T) {
	f := newFloor(nil)
	require.NotEmpty(t, f.auditLogPath, "test environment must resolve an audit log path")

	cases := []struct {
		name string
		bin  string
		args []string
		want bool
	}{
		{"rm on the log", "rm", []string{"-f", f.auditLogPath}, true},
		{"shred on the log", "shred", []string{f.auditLogPath}, true},
		{"dd of= the log", "dd", []string{"if=/dev/zero", "of=" + f.auditLogPath}, true},
		{"rm -rf on the parent dir", "rm", []string{"-rf", f.auditLogPath[:len(f.auditLogPath)-len("/audit.log")]}, true},
		{"rm on an unrelated file", "rm", []string{"/tmp/unrelated.txt"}, false},
		{"cat (non-mutating) on the log", "cat", []string{f.auditLogPath}, false},
	}
	for _, c := range cases {
		hit, ok := f.eval(c.bin, c.args)
		if c.want {
			require.True(t, ok, c.name)
			assert.Equal(t, floorAuditLogDestruction, hit.rule, c.name)
		} else {
			assert.False(t, ok, c.name)
		}
	}
}

// TestFloorRuleCodes_ManifestStable: the shipped manifest is exactly the
// documented seven rules — a drifted floor set is a doctor FATAL.
func TestFloorRuleCodes_ManifestStable(t *testing.T) {
	assert.Equal(t, []string{
		"funnel-enable",
		"filevault-disable",
		"luks-erase",
		"audit-log-destruction",
		"tailnet-lock-disable",
		"ntfy-bind-all",
		"canary-tripwire",
	}, FloorRuleCodes())
}

// TestFloor_TailnetLockAndBindRules covers the remaining floor shapes.
func TestFloor_TailnetLockAndBindRules(t *testing.T) {
	f := newFloor(nil)

	hit, ok := f.eval("tailscale", []string{"lock", "local-disable"})
	require.True(t, ok)
	assert.Equal(t, floorTailnetLockDisable, hit.rule)

	_, ok = f.eval("tailscale", []string{"lock", "status"})
	assert.False(t, ok, "a lock status query must not trip the floor")

	hit, ok = f.eval("ntfy", []string{"serve", "--listen-http", "0.0.0.0:2586"})
	require.True(t, ok)
	assert.Equal(t, floorNtfyBindAll, hit.rule)

	_, ok = f.eval("ntfy", []string{"serve", "--listen-http", "100.64.0.7:2586"})
	assert.False(t, ok, "a tailnet-IP bind must not trip the floor")
}
