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

package deadman

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/require"
)

// newTestRegistry returns a Registry backed by a temp state file and a temp
// audit log, plus the resolved state path and audit-log path for assertions.
func newTestRegistry(t *testing.T) (*Registry, string, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "armed-runs.json")
	logPath := filepath.Join(dir, "audit.log")
	aud := audit.New(logPath)
	return New(statePath, aud), statePath, logPath
}

// TestRegisterListDeregister covers the core lifecycle plus cross-process
// persistence (a fresh Registry instance over the same state file sees a run
// registered by an earlier instance).
func TestRegisterListDeregister(t *testing.T) {
	reg, statePath, _ := newTestRegistry(t)

	run := ArmedRun{PGID: 1234, ClosureHash: "deadbeef", ArmedAt: time.Unix(1000, 0).UTC()}
	require.NoError(t, reg.Register(run))

	runs, err := reg.List()
	require.NoError(t, err)
	require.Len(t, runs, 1)
	require.Equal(t, 1234, runs[0].PGID)
	require.Equal(t, "deadbeef", runs[0].ClosureHash)

	// Cross-process persistence: a fresh Registry instance over the same state
	// file (different in-memory object, simulating a separate process) sees it.
	aud := audit.New(filepath.Join(filepath.Dir(statePath), "audit.log"))
	fresh := New(statePath, aud)
	runs2, err := fresh.List()
	require.NoError(t, err)
	require.Len(t, runs2, 1)
	require.Equal(t, 1234, runs2[0].PGID)

	// Deregister removes it.
	require.NoError(t, reg.Deregister(1234))
	runs3, err := reg.List()
	require.NoError(t, err)
	require.Empty(t, runs3)
}

// TestDeregisterAbsentIsNoop asserts deregistering a pgid that was never
// registered is a no-op, not an error.
func TestDeregisterAbsentIsNoop(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	require.NoError(t, reg.Deregister(99999))

	// Register one, then deregister a different absent pgid: the registered run
	// must survive.
	require.NoError(t, reg.Register(ArmedRun{PGID: 7, ClosureHash: "aa", ArmedAt: time.Now().UTC()}))
	require.NoError(t, reg.Deregister(8))
	runs, err := reg.List()
	require.NoError(t, err)
	require.Len(t, runs, 1)
	require.Equal(t, 7, runs[0].PGID)
}

// TestRegisterWritesThroughAudit asserts the state file mutation is recorded in
// the audit log (the tamper-evident path), proving it was NOT a bare
// os.WriteFile (T-32-19).
func TestRegisterWritesThroughAudit(t *testing.T) {
	reg, statePath, logPath := newTestRegistry(t)

	require.NoError(t, reg.Register(ArmedRun{PGID: 42, ClosureHash: "cafe", ArmedAt: time.Now().UTC()}))

	// The audit log exists and records a mutation of the state file path.
	logBytes, err := os.ReadFile(logPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	require.Contains(t, string(logBytes), statePath,
		"audit log must record the armed-runs.json mutation (proves audit-written, not os.WriteFile)")
}

// TestListMissingFileEmpty asserts List on a never-written state file returns an
// empty slice, not an error.
func TestListMissingFileEmpty(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	runs, err := reg.List()
	require.NoError(t, err)
	require.Empty(t, runs)
}

// TestConcurrentRegisterNoLostUpdate asserts two Registry instances over the
// same state file registering concurrently do not lose either entry — the
// read-modify-write goes through the cross-process audit Update lock.
func TestConcurrentRegisterNoLostUpdate(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "armed-runs.json")
	logPath := filepath.Join(dir, "audit.log")

	regA := New(statePath, audit.New(logPath))
	regB := New(statePath, audit.New(logPath))

	const nEach = 25
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < nEach; i++ {
			require.NoError(t, regA.Register(ArmedRun{PGID: 1000 + i, ClosureHash: "a", ArmedAt: time.Now().UTC()}))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < nEach; i++ {
			require.NoError(t, regB.Register(ArmedRun{PGID: 2000 + i, ClosureHash: "b", ArmedAt: time.Now().UTC()}))
		}
	}()
	wg.Wait()

	runs, err := regA.List()
	require.NoError(t, err)
	require.Len(t, runs, 2*nEach, "no Register may be lost under concurrent cross-process writes")
}
