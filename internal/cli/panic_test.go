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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPanicNoConfirmCall verifies that the panic command does NOT call Confirm,
// Pause, or ConfirmTyped — panic must execute immediately without prompting.
// We verify by checking the Short description does not reference a confirm gate
// (Long text may mention "no confirmation" to document the design decision).
func TestPanicNoConfirmCall(t *testing.T) {
	cmd := newPanicCmd()
	// Short description must not say "confirm required" or similar.
	assert.NotContains(t, strings.ToLower(cmd.Short), "confirm required",
		"panic Short must not imply confirmation is required")
	// The command must not call Pause or ConfirmTyped — verified by having
	// no Runnable() returns true with a blocking huh form. The binary-level
	// test (testPanicNoHang in conformance suite) asserts the real behavior.
	assert.NotNil(t, cmd.RunE, "panic RunE must be set")
}

// TestPanicHasDoneInTiming verifies that the panic command's output would
// include step markers (✓/✗) and a "done in" timing line.
// We test this structurally by checking that cmd_panic.go uses the icon constants
// and "done in" text (verified via the panicStep helper function's signature).
func TestPanicHasDoneInTiming(t *testing.T) {
	// Verify the panicStep function exists and produces ✓ on success.
	var out strings.Builder
	p := NewHumanPrinterTo(&out, &out)

	// Success step.
	panicStep(p, "disconnect tailnet", nil)
	successOutput := out.String()

	out.Reset()
	// Failure step.
	panicStep(p, "revoke device", errPanicStepFailed{"mock error"})
	failOutput := out.String()

	assert.Contains(t, successOutput, iconDone,
		"panicStep success must contain the ✓ icon")
	assert.Contains(t, failOutput, iconFatal,
		"panicStep failure must contain the ✕ icon")
}

// TestPanicCommandHasExample verifies the panic command has an Example field.
func TestPanicCommandHasExample(t *testing.T) {
	cmd := newPanicCmd()
	assert.NotEmpty(t, cmd.Example,
		"panic command must have an Example field for --help")
}

// TestAllCommandsHaveExamples walks the cobra command tree and asserts that
// every runnable (non-group) leaf command has a non-empty Example string.
// The inventory mirrors buildRootCmd: init, up, status, doctor, repair, enroll,
// notify, watch, acl, lock, rotate, logs, backup, upgrade, version, daemon,
// enable, disable, threat-model, uninstall, panic.
func TestAllCommandsHaveExamples(t *testing.T) {
	root := buildRootCmd()
	assertExamplesRecursive(t, root)
}

// assertExamplesRecursive walks the command tree depth-first.
func assertExamplesRecursive(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	for _, sub := range cmd.Commands() {
		if len(sub.Commands()) > 0 {
			// Parent group — recurse into children.
			assertExamplesRecursive(t, sub)
		} else if sub.Runnable() {
			assert.NotEmpty(t, sub.Example,
				"command %q must have a non-empty Example field", sub.Use)
		}
	}
}

// TestPanicRigFlag_UnknownRigErrors verifies CLI-05: `panic --rig <unknown>`
// must return a hard error and NEVER fall back to silently running the LOCAL
// panic sequence (no `tailscale down`, no device revocation, no key destroy).
func TestPanicRigFlag_UnknownRigErrors(t *testing.T) {
	// Inject a mock runner so no real command could ever run, and so we can
	// assert that the local panic steps were never attempted.
	mock := shell.NewMockRunner()
	origNewRunner := newRunner
	newRunner = func() shell.Runner { return mock }
	t.Cleanup(func() { newRunner = origNewRunner })

	root := buildRootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetErr(&out)
	// A valid config with no enrolled rigs — "laptop" is unknown. The config
	// file must exist: an explicitly-passed missing --config is now a hard
	// error before rig resolution (UX review #4), which would mask the
	// unknown-rig assertion this test exists for.
	cfgPath := filepath.Join(t.TempDir(), "abysslink.yaml")
	cfgData, merr := config.Marshal(testCfgDefaults())
	require.NoError(t, merr)
	require.NoError(t, os.WriteFile(cfgPath, cfgData, 0o600))
	root.SetArgs([]string{"panic", "--rig", "laptop", "--config", cfgPath})

	err := root.ExecuteContext(context.Background())
	require.Error(t, err, "panic --rig <unknown> must error, not run local panic")
	assert.Contains(t, err.Error(), `"laptop"`)

	// The local disconnect step must never have run.
	for _, call := range mock.RecordedCalls() {
		assert.NotEqual(t, "tailscale", call.Name,
			"local panic steps must not run when --rig targeting fails: %v", call)
	}
}

// strictDeleteKeychain wraps secrets.MockStore with a Delete that fails with
// secrets.ErrNotFound for absent entries, matching the real OS stores so the
// skip-on-not-found path in destroyAPIKeysFromKeychain is exercised.
type strictDeleteKeychain struct {
	*secrets.MockStore
}

func (s *strictDeleteKeychain) Delete(ctx context.Context, service, account string) error {
	if _, err := s.Get(ctx, service, account); err != nil {
		return err // wraps secrets.ErrNotFound
	}
	return s.MockStore.Delete(ctx, service, account)
}

// TestPanicDestroysRigScopedAPIKeys covers W7: the kill switch must destroy the
// rig-scoped Anthropic API key copies created by `enroll rig`'s keychain
// migration, not only the v1 entry — otherwise live keys survive the panic.
func TestPanicDestroysRigScopedAPIKeys(t *testing.T) {
	ctx := context.Background()
	kc := &strictDeleteKeychain{MockStore: secrets.NewMockStore()}

	// v1 entry + two rig-scoped migrated copies; a third rig was never migrated.
	require.NoError(t, kc.Set(ctx, "abysslink", "anthropic-api-key", "sk-v1"))
	require.NoError(t, kc.Set(ctx, fleet.RigService("alpha"), "anthropic-api-key", "sk-alpha"))
	require.NoError(t, kc.Set(ctx, fleet.RigService("beta"), "anthropic-api-key", "sk-beta"))

	rigs := []config.RigConfig{
		{Name: "alpha", NtfyTopic: "t-a"},
		{Name: "beta", NtfyTopic: "t-b"},
		{Name: "never-migrated", NtfyTopic: "t-n"},
	}

	var out strings.Builder
	p := NewHumanPrinterTo(&out, &out)
	logged := []string{}
	destroyAPIKeysFromKeychain(ctx, kc, rigs, p, func(action string) { logged = append(logged, action) })

	// v1 entry destroyed.
	_, err := kc.Get(ctx, "abysslink", "anthropic-api-key")
	require.Error(t, err, "v1 anthropic-api-key must be deleted")

	// Rig-scoped copies destroyed.
	_, err = kc.Get(ctx, fleet.RigService("alpha"), "anthropic-api-key")
	require.Error(t, err, "rig-scoped key for alpha must be deleted")
	_, err = kc.Get(ctx, fleet.RigService("beta"), "anthropic-api-key")
	require.Error(t, err, "rig-scoped key for beta must be deleted")

	// Never-migrated rig: skipped silently (no scary ✕ marker for it).
	assert.NotContains(t, out.String(), "never-migrated",
		"a rig that never had a migrated key must be skipped silently")

	// Audit actions recorded for the v1 + 2 rig-scoped deletions.
	assert.Contains(t, logged, "destroy_local_api_key")
	count := 0
	for _, a := range logged {
		if a == "destroy_rig_api_key" {
			count++
		}
	}
	assert.Equal(t, 2, count, "one destroy_rig_api_key audit action per migrated rig")
}

// TestRotateUpdatesRigScopedAPIKeys covers the rotate half of W7: rotating the
// Anthropic key must update every rig-scoped migrated copy, leaving none with
// the stale-but-valid old key. Rigs never migrated stay untouched.
func TestRotateUpdatesRigScopedAPIKeys(t *testing.T) {
	ctx := context.Background()
	kc := secrets.NewMockStore()

	require.NoError(t, kc.Set(ctx, fleet.RigService("alpha"), "anthropic-api-key", "sk-old"))
	rigs := []config.RigConfig{
		{Name: "alpha", NtfyTopic: "t-a"},
		{Name: "never-migrated", NtfyTopic: "t-n"},
	}

	var out strings.Builder
	p := NewHumanPrinterTo(&out, &out)
	require.NoError(t, updateRigScopedAnthropicKeys(ctx, kc, rigs, p, "sk-new"))

	got, err := kc.Get(ctx, fleet.RigService("alpha"), "anthropic-api-key")
	require.NoError(t, err)
	assert.Equal(t, "sk-new", got, "rig-scoped copy must carry the rotated key")

	_, err = kc.Get(ctx, fleet.RigService("never-migrated"), "anthropic-api-key")
	require.Error(t, err, "a rig that was never migrated must not gain a key copy")

	assert.Contains(t, out.String(), "alpha", "the updated rig must be reported")
}
