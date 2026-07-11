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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
	"github.com/abysslink/abysslink/internal/duress"
	"github.com/abysslink/abysslink/internal/secrets"
)

// recordingAppender captures audit calls so tests can assert the entry is
// generic and leaks nothing about the credential.
type recordingAppender struct {
	mu      sync.Mutex
	entries []struct {
		op, target string
		content    []byte
		dryRun     bool
	}
}

func (r *recordingAppender) Append(op, target string, content []byte, dryRun bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, struct {
		op, target string
		content    []byte
		dryRun     bool
	}{op, target, content, dryRun})
	return nil
}

// enrolledStore returns a MockStore holding argon2id digests for a real and a
// decoy passphrase, plus the enabled config to resolve them.
func enrolledStore(t *testing.T, realPass, decoyPass string) (config.DuressConfig, secrets.KeychainStore) {
	t.Helper()
	store := secrets.NewMockStore()
	ctx := context.Background()
	realPHC, err := duress.HashCredential(realPass)
	require.NoError(t, err)
	decoyPHC, err := duress.HashCredential(decoyPass)
	require.NoError(t, err)
	// The digest is single-line (the mock/real backends reject newlines).
	require.NotContains(t, realPHC, "\n")
	require.NoError(t, store.Set(ctx, duress.KeychainService, duress.RealAccount, realPHC))
	require.NoError(t, store.Set(ctx, duress.KeychainService, duress.DecoyAccount, decoyPHC))
	return config.DuressConfig{Enabled: true, SecretSource: config.DuressSecretSourceKeychain}, store
}

func TestResolve_Outcomes(t *testing.T) {
	ctx := context.Background()
	cfg, store := enrolledStore(t, "correct horse battery staple", "hunter2 decoy")

	assert.Equal(t, duress.ModeReal, duress.Resolve(ctx, "correct horse battery staple", cfg, store),
		"the real credential resolves to the real view")
	assert.Equal(t, duress.ModeDecoy, duress.Resolve(ctx, "hunter2 decoy", cfg, store),
		"the decoy credential resolves to the decoy view")
	assert.Equal(t, duress.ModeNone, duress.Resolve(ctx, "totally wrong", cfg, store),
		"a non-matching credential is the normal auth failure")
	// A short and a long non-match both resolve None: the compare is over
	// fixed-width digests, so no length side-channel exists.
	assert.Equal(t, duress.ModeNone, duress.Resolve(ctx, "x", cfg, store))
	assert.Equal(t, duress.ModeNone, duress.Resolve(ctx, strings.Repeat("y", 4096), cfg, store))
}

func TestResolve_FailsClosed(t *testing.T) {
	ctx := context.Background()
	cfg, store := enrolledStore(t, "realpw", "decoypw")

	t.Run("disabled_resolves_none", func(t *testing.T) {
		off := cfg
		off.Enabled = false
		assert.Equal(t, duress.ModeNone, duress.Resolve(ctx, "realpw", off, store),
			"a disabled feature never resolves to the real view")
	})
	t.Run("secret_source_none_resolves_none", func(t *testing.T) {
		src := cfg
		src.SecretSource = "none"
		assert.Equal(t, duress.ModeNone, duress.Resolve(ctx, "realpw", src, store))
	})
	t.Run("nil_store_resolves_none", func(t *testing.T) {
		assert.Equal(t, duress.ModeNone, duress.Resolve(ctx, "realpw", cfg, nil),
			"a nil/degraded store fails closed, never opens the real view")
	})
	t.Run("only_decoy_enrolled", func(t *testing.T) {
		s := secrets.NewMockStore()
		phc, err := duress.HashCredential("decoyonly")
		require.NoError(t, err)
		require.NoError(t, s.Set(ctx, duress.KeychainService, duress.DecoyAccount, phc))
		assert.Equal(t, duress.ModeDecoy, duress.Resolve(ctx, "decoyonly", cfg, s))
		assert.Equal(t, duress.ModeNone, duress.Resolve(ctx, "anything-real", cfg, s),
			"with no real slot enrolled, only the decoy can match")
	})
}

func TestDecoyRigView_Benign(t *testing.T) {
	v := duress.DecoyRigView(config.DecoyConfig{Enabled: true})
	assert.Zero(t, v.Fleet, "the benign view hides any real fleet")
	assert.Zero(t, v.Sessions, "the benign view shows no live sessions")
	assert.Zero(t, v.Armed, "the benign view shows no armed agents")
	assert.NotEmpty(t, v.Hostname, "the benign view still shows a plausible hostname")

	named := duress.DecoyRigView(config.DecoyConfig{Enabled: true, Hostname: "quiet-laptop"})
	assert.Equal(t, "quiet-laptop", named.Hostname)
}

// TestTrigger_RealDegradationGenericAudit asserts the decoy trigger performs a
// REAL degradation (freezes/kills the armed pgid + latches the lockdown) and
// records exactly ONE generic audit entry that reveals nothing about which
// credential was used (DUR-02/DUR-03).
func TestTrigger_RealDegradationGenericAudit(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()

	logPath := filepath.Join(t.TempDir(), "audit.log")
	aud := audit.New(logPath)

	statePath, err := deadman.StatePath()
	require.NoError(t, err)
	reg := deadman.New(statePath, aud)
	require.NoError(t, reg.Register(deadman.ArmedRun{PGID: 4242, ClosureHash: "deadbeefcafef00d"}))

	flagPath, err := deadman.LockdownFlagPath()
	require.NoError(t, err)

	var mu sync.Mutex
	var signals []syscall.Signal
	rec := &recordingAppender{}

	err = duress.Trigger(ctx, duress.TriggerOpts{
		Registry:        reg,
		FlagPath:        flagPath,
		LockdownUpdater: aud,
		Audit:           rec,
		SignalFn: func(pgid int, sig syscall.Signal) error {
			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, 4242, pgid, "only the registered armed pgid is signalled")
			signals = append(signals, sig)
			return nil
		},
	})
	require.NoError(t, err)

	// Real degradation: the armed pgid was signalled (SIGTERM then SIGKILL) and
	// deregistered.
	mu.Lock()
	assert.Equal(t, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}, signals)
	mu.Unlock()
	runs, err := reg.List()
	require.NoError(t, err)
	assert.Empty(t, runs, "the disarmed pgid is deregistered")

	// The lockdown latch is set so a fresh agent cannot silently re-arm.
	locked, reason, err := deadman.IsLockedDown(flagPath)
	require.NoError(t, err)
	assert.True(t, locked, "the persisted lockdown latch is set")
	assert.NotContains(t, strings.ToLower(reason), "decoy", "the latch reason must not reveal decoy-vs-real")

	// Exactly one generic audit entry, with no decoy-vs-real discriminator and
	// no credential body.
	require.Len(t, rec.entries, 1)
	e := rec.entries[0]
	assert.Equal(t, "session-degraded", e.op)
	assert.Equal(t, "session", e.target)
	assert.Nil(t, e.content, "no credential body is audited")
	assert.False(t, e.dryRun, "a real degradation is not a dry-run")
	assert.NotContains(t, strings.ToLower(e.op+" "+e.target), "decoy",
		"the audit entry must not reveal the credential was a decoy")
	assert.NotContains(t, strings.ToLower(e.op+" "+e.target), "real")
}

// TestTrigger_NilRegistryLatchesOnly proves a CLI invocation with no daemon-
// owned registry still latches the lockdown (stops future arms) without error.
func TestTrigger_NilRegistryLatchesOnly(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()
	aud := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	flagPath, err := deadman.LockdownFlagPath()
	require.NoError(t, err)

	require.NoError(t, duress.Trigger(ctx, duress.TriggerOpts{
		Registry:        nil,
		FlagPath:        flagPath,
		LockdownUpdater: aud,
		Audit:           &recordingAppender{},
	}))
	locked, _, err := deadman.IsLockedDown(flagPath)
	require.NoError(t, err)
	assert.True(t, locked)
}
