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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
	"github.com/abysslink/abysslink/internal/duress"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

// writeDuressCfg writes a config with the duress decoy enabled and returns its
// path; XDG_STATE_HOME points at the sandbox so audit/deadman state files land
// under the test dir.
func writeDuressCfg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	cfg.Duress = config.DuressConfig{Enabled: true, SecretSource: config.DuressSecretSourceKeychain}
	cfg.Decoy = config.DecoyConfig{Enabled: true, Hostname: "quiet-laptop"}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// runDuressCLI executes `abysslink duress <args...>` with the given stdin.
func runDuressCLI(t *testing.T, cfgPath, stdin string, args ...string) (string, error) {
	t.Helper()
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(stdin))
	full := append([]string{"duress"}, args...)
	full = append(full, "--config", cfgPath)
	root.SetArgs(full)
	err := root.Execute()
	return out.String(), err
}

// injectMockKeychain swaps the unlock keychain seam for an in-memory MockStore
// pre-enrolled with the given real + decoy passphrases (NEVER a live keychain).
func injectMockKeychain(t *testing.T, realPass, decoyPass string) {
	t.Helper()
	store := secrets.NewMockStore()
	ctx := context.Background()
	realPHC, err := duress.HashCredential(realPass)
	require.NoError(t, err)
	decoyPHC, err := duress.HashCredential(decoyPass)
	require.NoError(t, err)
	require.NoError(t, store.Set(ctx, duress.KeychainService, duress.RealAccount, realPHC))
	require.NoError(t, store.Set(ctx, duress.KeychainService, duress.DecoyAccount, decoyPHC))
	prev := duressKeychainFn
	duressKeychainFn = func(context.Context, shell.Runner) (secrets.KeychainStore, error) { return store, nil }
	t.Cleanup(func() { duressKeychainFn = prev })
}

// TestUnlock_Indistinguishable asserts a decoy unlock and a real unlock of an
// idle machine produce byte-identical output, and that a non-match produces the
// verbatim auth-failure with a non-nil (exit) error (DUR-02).
func TestUnlock_Indistinguishable(t *testing.T) {
	cfgPath := writeDuressCfg(t)
	injectMockKeychain(t, "real-pass", "decoy-pass")

	decoyOut, decoyErr := runDuressCLI(t, cfgPath, "decoy-pass\n", "unlock")
	require.NoError(t, decoyErr)

	// A real unlock of an idle machine (0 fleet) with the same hostname must
	// render byte-for-byte identically. Re-enrol against a config whose real
	// hostname matches the decoy hostname and no rigs, then unlock with the real
	// credential.
	idlePath := writeDuressCfg(t)
	// Point the real hostname at the decoy hostname + zero fleet so the real
	// idle render equals the decoy render.
	idleCfg, err := config.Load(idlePath)
	require.NoError(t, err)
	idleCfg.Tailnet.Hostname = "quiet-laptop"
	idleCfg.Rigs = nil
	data, err := yaml.Marshal(idleCfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(idlePath, data, 0o600))
	injectMockKeychain(t, "real-pass", "decoy-pass")
	realOut, realErr := runDuressCLI(t, idlePath, "real-pass\n", "unlock")
	require.NoError(t, realErr)

	assert.Equal(t, realOut, decoyOut,
		"a decoy unlock must be byte-for-byte indistinguishable from a real idle unlock")

	// Non-match: verbatim auth failure + a non-nil error (exit code).
	noneOut, noneErr := runDuressCLI(t, cfgPath, "wrong-pass\n", "unlock")
	require.Error(t, noneErr)
	assert.Contains(t, noneOut, authFailMessage)
}

// TestUnlock_DecoyDegradesSession asserts the decoy path fires the REAL
// kill-switch degradation (the persisted lockdown latch is set so a fresh agent
// cannot re-arm) while the visible output stays a benign view. The live-pgid
// disarm ladder is exercised with an injected signal fn in the duress package
// unit test; here the empty registry means no real process group is signalled.
func TestUnlock_DecoyDegradesSession(t *testing.T) {
	cfgPath := writeDuressCfg(t)
	injectMockKeychain(t, "real-pass", "decoy-pass")

	out, err := runDuressCLI(t, cfgPath, "decoy-pass\n", "unlock")
	require.NoError(t, err)
	assert.Contains(t, out, "quiet-laptop", "the benign view is shown")

	flagPath, err := deadman.LockdownFlagPath()
	require.NoError(t, err)
	locked, _, err := deadman.IsLockedDown(flagPath)
	require.NoError(t, err)
	assert.True(t, locked, "the decoy trigger sets the persisted lockdown latch")

	// The lockdown latch reason must not reveal decoy-vs-real (DUR-03).
	_, reason, err := deadman.IsLockedDown(flagPath)
	require.NoError(t, err)
	assert.NotContains(t, strings.ToLower(reason), "decoy")
}

// TestDuressEnable_DryRunDefault asserts enable without --apply persists nothing
// (dry-run default) and never touches a live keychain.
func TestDuressEnable_DryRunDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	out, err := runDuressCLI(t, cfgPath, "real-pass\ndecoy-pass\n", "enable")
	require.NoError(t, err)
	assert.Contains(t, out, "[plan]")

	loaded, lErr := config.Load(cfgPath)
	require.NoError(t, lErr)
	assert.False(t, loaded.Duress.Enabled, "dry-run must NOT persist the enable")
}

// TestDuressEnable_RejectsIdenticalCreds asserts a real==decoy enrolment fails
// (a decoy that equals the real credential is useless).
func TestDuressEnable_RejectsIdenticalCreds(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	_, err = runDuressCLI(t, cfgPath, "samepass\nsamepass\n", "enable", "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must differ")
}

// TestUnlock_DecoyEmitsNoLogs is the regression for the CRITICAL indistinguishability
// gap the skeptic panel found: the degradation seam logs via the process-global
// slog default (which BYPASSES cobra's captured out/err buffer), so a decoy unlock
// printed WARN lines literally naming "duress" and "lockdown" to the real terminal
// while a real unlock printed none — trivially visible to the shoulder-surfer the
// decoy exists to defeat. fireDuressTrigger must silence ALL degradation logging.
//
// We install a capturing handler as the slog default; fireDuressTrigger swaps it
// for a discard handler while degrading and restores ours afterwards, so a decoy
// unlock must leave the capture buffer empty AND restore our handler.
func TestUnlock_DecoyEmitsNoLogs(t *testing.T) {
	cfgPath := writeDuressCfg(t)
	injectMockKeychain(t, "real-pass", "decoy-pass")

	var logBuf bytes.Buffer
	captured := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prev := slog.Default()
	slog.SetDefault(captured)
	t.Cleanup(func() { slog.SetDefault(prev) })

	out, err := runDuressCLI(t, cfgPath, "decoy-pass\n", "unlock")
	require.NoError(t, err)
	assert.Contains(t, out, "quiet-laptop", "the benign view is still shown")

	got := strings.ToLower(logBuf.String())
	assert.NotContains(t, got, "duress", "the decoy path must not log the word 'duress' to the default handler")
	assert.NotContains(t, got, "lockdown", "the decoy path must not log 'lockdown' to the default handler")
	assert.NotContains(t, got, "disarm", "the decoy path must not log 'disarm' to the default handler")
	assert.Empty(t, logBuf.String(), "a decoy unlock must be silent on the slog default handler")
	assert.Equal(t, captured, slog.Default(), "fireDuressTrigger must restore the previous default logger")
}
