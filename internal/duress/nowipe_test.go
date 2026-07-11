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

package duress_test

import (
	"context"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
	"github.com/abysslink/abysslink/internal/duress"
)

// forbiddenCalls are selector names that would delete, truncate, or overwrite
// real data (filesystem) or revoke credentials — a destructive duress-wipe is
// an EXPLICIT anti-feature. The duress package must contain NONE of them: the
// decoy is pure read-substitution plus a reversible latch. Additive writes go
// through deadman.SetLockdownFlag (audit-written), not these.
var forbiddenCalls = map[string]bool{
	"Remove":    true, // os.Remove
	"RemoveAll": true, // os.RemoveAll
	"Truncate":  true, // os.Truncate / file.Truncate
	"WriteFile": true, // os.WriteFile (must go through internal/audit)
	"Unlink":    true, // syscall.Unlink
	"RevokeAll": true, // device.Store.RevokeAll
}

// TestNoDestructiveCalls_StaticScan parses every non-test source file in this
// package and fails if any forbidden destructive call appears. This is the
// structural no-wipe guarantee (DUR-01).
func TestNoDestructiveCalls_StaticScan(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	scanned := 0
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, perr, "parse %s", name)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if forbiddenCalls[sel.Sel.Name] {
				t.Errorf("%s: forbidden destructive call %q — the duress package must have NO wipe/delete/truncate path", name, sel.Sel.Name)
			}
			return true
		})
	}
	require.NotZero(t, scanned, "expected to scan at least one source file")
}

// TestTrigger_LeavesRealDataIntact is the behavioural half of the no-wipe
// guarantee: after a duress trigger the real config is byte-for-byte unchanged,
// still loads to the real fleet, and no state file is deleted or truncated —
// only the additive lockdown latch appears.
func TestTrigger_LeavesRealDataIntact(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()

	// A real config on disk carrying a real fleet.
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "abysslink.yaml")
	realYAML := "version: 1\n" +
		"identity:\n  email: op@example.com\n  unix_user: op\n" +
		"tailnet:\n  hostname: real-rig\n" +
		"rigs:\n  - name: laptop\n    hostname: laptop.example.ts.net\n" +
		"  - name: desktop\n    hostname: desktop.example.ts.net\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(realYAML), 0o600))

	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	beforeHash := sha256.Sum256(before)

	// Sanity: the config loads to the real fleet before the trigger.
	preCfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, preCfg.Rigs, 2)

	aud := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	statePath, err := deadman.StatePath()
	require.NoError(t, err)
	reg := deadman.New(statePath, aud)
	require.NoError(t, reg.Register(deadman.ArmedRun{PGID: 5252, ClosureHash: "abad1deaabad1dea"}))
	flagPath, err := deadman.LockdownFlagPath()
	require.NoError(t, err)

	require.NoError(t, duress.Trigger(ctx, duress.TriggerOpts{
		Registry:        reg,
		FlagPath:        flagPath,
		LockdownUpdater: aud,
		Audit:           &recordingAppender{},
		SignalFn:        func(int, syscall.Signal) error { return nil },
	}))

	// The real config is byte-for-byte unchanged and still loads to the real
	// fleet — the decoy degraded the SESSION, never the DATA.
	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	afterHash := sha256.Sum256(after)
	assert.Equal(t, beforeHash, afterHash, "the real config must be byte-for-byte unchanged")

	postCfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Len(t, postCfg.Rigs, 2, "the real fleet is still fully present after a duress trigger")

	// The armed-runs state file still exists (the run was deregistered additively,
	// not the file wiped) and the ONLY new state artifact is the lockdown latch.
	_, statErr := os.Stat(statePath)
	assert.NoError(t, statErr, "the registry state file is not deleted")
	_, flagErr := os.Stat(flagPath)
	assert.NoError(t, flagErr, "the additive lockdown latch is created")
}
