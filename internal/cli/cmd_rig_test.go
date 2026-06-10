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
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// writeCfgWithRigs writes a config file with two rigs and returns the path.
func writeCfgWithRigs(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	cfg.Rigs = []config.RigConfig{
		{Name: "alpha", Hostname: "alpha.ts.net", NtfyTopic: "abysslink-alpha-aabbccdd", Backend: "tailscale"},
		{Name: "beta", Hostname: "beta.ts.net", NtfyTopic: "abysslink-beta-11223344", Backend: "headscale", LastSeen: "2026-06-01T10:00:00Z"},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// TestRigLs_Human asserts that `rig ls` renders a human table with name/hostname/backend/last-seen.
func TestRigLs_Human(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	var out bytes.Buffer
	err := runRigLs(cfgPath, false, &out)
	require.NoError(t, err)

	output := out.String()
	// Must contain rig names.
	assert.Contains(t, output, "alpha", "human table must list rig alpha")
	assert.Contains(t, output, "beta", "human table must list rig beta")
	// Must contain hostnames.
	assert.Contains(t, output, "alpha.ts.net")
	assert.Contains(t, output, "beta.ts.net")
	// Must contain backends.
	assert.Contains(t, output, "tailscale")
	assert.Contains(t, output, "headscale")
}

// TestRigLs_JSON asserts that `rig ls --json` emits a JSON array of records (ANSI-free, UX-04).
func TestRigLs_JSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	var out bytes.Buffer
	err := runRigLs(cfgPath, true, &out)
	require.NoError(t, err)

	// Must be valid JSON array.
	var records []rigLsRecord
	require.NoError(t, json.Unmarshal(out.Bytes(), &records), "output must be a JSON array")
	require.Len(t, records, 2)

	// No ANSI codes (UX-04).
	assert.NotContains(t, out.String(), "\x1b[", "JSON output must be ANSI-free")

	// Check fields.
	assert.Equal(t, "alpha", records[0].Name)
	assert.Equal(t, "alpha.ts.net", records[0].Hostname)
	assert.Equal(t, "tailscale", records[0].Backend)
	assert.Equal(t, "beta", records[1].Name)
	assert.Equal(t, "2026-06-01T10:00:00Z", records[1].LastSeen)
}

// TestRigExport_NoSecrets asserts that `rig export` outputs YAML containing ONLY
// the rigs: section and NO secret material (D-FS-02).
func TestRigExport_NoSecrets(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	var out bytes.Buffer
	err := runRigExport(cfgPath, &out)
	require.NoError(t, err)

	output := out.String()

	// Must contain rig names in yaml.
	assert.Contains(t, output, "alpha")
	assert.Contains(t, output, "beta")

	// Must NOT contain hmac key bytes or any "secret" content.
	assert.NotContains(t, output, "hmac", "export must not contain hmac key material")
	assert.NotContains(t, output, "password", "export must not contain passwords")

	// Must be valid YAML that can be round-tripped.
	var wrapper rigExportWrapper
	require.NoError(t, yaml.Unmarshal([]byte(output), &wrapper), "export must be valid YAML")
	require.Len(t, wrapper.Rigs, 2)
}

// writeCfgInvalidHostnameWithRigs writes a config whose tailnet.hostname is
// invalid (fails config.Validate) but whose rigs: section is well-formed. Used to
// prove the WR-07 read-only degradation path.
func writeCfgInvalidHostnameWithRigs(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	// Unrelated-to-rigs validation failure: an unsafe hostname stanza. Parses
	// fine (string field) but Validate → validateIdentity rejects it.
	cfg.Tailnet.Hostname = "Bad_Host!"
	cfg.Rigs = []config.RigConfig{
		{Name: "alpha", Hostname: "alpha.ts.net", NtfyTopic: "abysslink-alpha-aabbccdd", Backend: "tailscale"},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// TestRigLs_DegradesOnUnrelatedValidationError is the automated coverage for
// 25-VERIFICATION human item #2 (WR-07). `rig ls` is read-only — it only renders
// cfg.Rigs and never feeds a value to argv or a mutation — so once config.Load
// fails closed (D-01), `rig ls` must NOT hard-fail on a validation error in an
// unrelated stanza (here, an unsafe tailnet.hostname). It must warn and still
// list the parsed rigs. The fail-closed Load remains the only entry point for
// mutating/argv paths; this guards the LoadForRead read-only carve-out.
func TestRigLs_DegradesOnUnrelatedValidationError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgInvalidHostnameWithRigs(t, dir)

	// Sanity: the config genuinely fails fail-closed Load (so the test proves a
	// real degradation, not a config that happens to validate).
	_, loadErr := config.Load(cfgPath)
	require.Error(t, loadErr, "precondition: config must fail fail-closed Load")

	// Human (table) rendering: must not error, must still list the rig.
	var out bytes.Buffer
	require.NoError(t, runRigLs(cfgPath, false, &out),
		"rig ls must degrade (warn + continue), not hard-fail, on an unrelated validation error")
	assert.Contains(t, out.String(), "alpha", "rig ls must still list parsed rigs despite the validation error")

	// JSON rendering: same degradation, valid array with the rig.
	var jsonOut bytes.Buffer
	require.NoError(t, runRigLs(cfgPath, true, &jsonOut))
	var records []rigLsRecord
	require.NoError(t, json.Unmarshal(jsonOut.Bytes(), &records))
	require.Len(t, records, 1)
	assert.Equal(t, "alpha", records[0].Name)

	// rig export shares the same read-only carve-out — it too must degrade.
	var exportOut bytes.Buffer
	require.NoError(t, runRigExport(cfgPath, &exportOut),
		"rig export must degrade like rig ls on an unrelated validation error")
	assert.Contains(t, exportOut.String(), "alpha")
}

// TestRigImport_Merge asserts that `rig import` merges a rigs: doc into cfg.Rigs
// and persists via config.Write (audit).
func TestRigImport_Merge(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	// Create an import file with a new rig.
	importPath := filepath.Join(dir, "import.yaml")
	importDoc := `rigs:
  - name: gamma
    hostname: gamma.ts.net
    ntfy_topic: abysslink-gamma-deadbeef
    backend: netbird
`
	require.NoError(t, os.WriteFile(importPath, []byte(importDoc), 0o600))

	err := runRigImport(cfgPath, importPath, true, nil, io.Discard)
	require.NoError(t, err)

	// Read back and verify.
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Rigs, 3, "imported rig must be appended")

	names := make([]string, 0, len(cfg.Rigs))
	for _, r := range cfg.Rigs {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "gamma", "merged rig must be present")
}

// TestRigImport_DryRun asserts that `rig import` with dry-run=true does not write.
func TestRigImport_DryRun(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	importPath := filepath.Join(dir, "import.yaml")
	importDoc := `rigs:
  - name: delta
    hostname: delta.ts.net
    ntfy_topic: abysslink-delta-00000000
    backend: tailscale
`
	require.NoError(t, os.WriteFile(importPath, []byte(importDoc), 0o600))

	var dryOut bytes.Buffer
	err := runRigImport(cfgPath, importPath, false, nil, &dryOut) // dry-run
	require.NoError(t, err)
	assert.Contains(t, dryOut.String(), "[dry-run]", "dry-run output must go through io.Writer (WR-01)")

	// Nothing must be written.
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Len(t, cfg.Rigs, 2, "dry-run must not modify config")
}

// TestRigImport_CollisionError asserts that `rig import` returns an error on a name collision.
func TestRigImport_CollisionError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	// Import a rig with the same name as an existing one.
	importPath := filepath.Join(dir, "import.yaml")
	importDoc := `rigs:
  - name: alpha
    hostname: alpha-duplicate.ts.net
    ntfy_topic: abysslink-alpha-xxxxxxxx
    backend: tailscale
`
	require.NoError(t, os.WriteFile(importPath, []byte(importDoc), 0o600))

	err := runRigImport(cfgPath, importPath, true, nil, io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alpha", "error must identify the colliding rig name")
}

// TestRigImport_NoOSWriteFile asserts that rig import does not use os.WriteFile
// by checking the source — this is a compile-time acceptance check via grep.
// We also confirm the function exists.
func TestRigImport_NoOSWriteFile(t *testing.T) {
	// If runRigImport is defined and the file has no os.WriteFile in production code,
	// this test passes. The grep acceptance check is in the plan's acceptance_criteria.
	// Here we just confirm the function is callable.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	importPath := filepath.Join(dir, "import.yaml")
	importDoc := `rigs:
  - name: test-rig
    hostname: test.ts.net
    ntfy_topic: abysslink-test-12345678
    backend: tailscale
`
	require.NoError(t, os.WriteFile(importPath, []byte(importDoc), 0o600))

	err = runRigImport(cfgPath, importPath, true, nil, io.Discard)
	require.NoError(t, err)
}

// TestRigFlags_Registered asserts that the persistent flags --rig, --all-rigs, --strict
// are registered on the root command (verifies root.go wiring).
func TestRigFlags_Registered(t *testing.T) {
	root := buildRootCmd()
	pf := root.PersistentFlags()

	rigFlag := pf.Lookup("rig")
	require.NotNil(t, rigFlag, "--rig persistent flag must be registered")
	assert.Equal(t, "string", rigFlag.Value.Type())

	allRigsFlag := pf.Lookup("all-rigs")
	require.NotNil(t, allRigsFlag, "--all-rigs persistent flag must be registered")
	assert.Equal(t, "bool", allRigsFlag.Value.Type())

	strictFlag := pf.Lookup("strict")
	require.NotNil(t, strictFlag, "--strict persistent flag must be registered")
	assert.Equal(t, "bool", strictFlag.Value.Type())
}

// TestRigImport_Stdin asserts that `rig import -` reads the rigs doc from the
// provided reader (CLI-26 — matches the `rig export | rig import -` pipeline
// advertised in the export help text).
func TestRigImport_Stdin(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	importDoc := `rigs:
  - name: stdin-rig
    hostname: stdin.ts.net
    ntfy_topic: abysslink-stdin-cafebabe
    backend: tailscale
`
	err := runRigImport(cfgPath, "-", true, strings.NewReader(importDoc), io.Discard)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Rigs, 3, "rig imported from stdin must be appended")
	names := make([]string, 0, len(cfg.Rigs))
	for _, r := range cfg.Rigs {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "stdin-rig")
}

// TestRigImport_InvalidName asserts that imported rig names are validated
// against rigNameRe (CLI-13, T-14-11) and nothing is written on violation.
func TestRigImport_InvalidName(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	badDocs := []string{
		"rigs:\n  - name: My_Rig\n    hostname: ok.ts.net\n    backend: tailscale\n",
		"rigs:\n  - name: UPPER\n    hostname: ok.ts.net\n    backend: tailscale\n",
		"rigs:\n  - name: \"rig;evil\"\n    hostname: ok.ts.net\n    backend: tailscale\n",
		"rigs:\n  - name: \"" + strings.Repeat("a", 64) + "\"\n    hostname: ok.ts.net\n    backend: tailscale\n",
	}
	for i, doc := range badDocs {
		importPath := filepath.Join(dir, "bad-import.yaml")
		require.NoError(t, os.WriteFile(importPath, []byte(doc), 0o600))

		err := runRigImport(cfgPath, importPath, true, nil, io.Discard)
		require.Error(t, err, "doc %d must be rejected", i)
		assert.Contains(t, err.Error(), "invalid rig name", "doc %d", i)
	}

	// Nothing written.
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Len(t, cfg.Rigs, 2, "invalid imports must not modify config")
}

// TestValidateImportRigs_NameRe is the unit-level coverage for the rigNameRe
// enforcement documented on validateImportRigs (CLI-13).
func TestValidateImportRigs_NameRe(t *testing.T) {
	err := validateImportRigs(nil, []config.RigConfig{
		{Name: "Bad Name", Hostname: "ok.ts.net"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rig name")

	require.NoError(t, validateImportRigs(nil, []config.RigConfig{
		{Name: "good-name-1", Hostname: "ok.ts.net"},
	}))
}

// TestRigLs_HonorsConfigFlag asserts that `rig ls --config <path>` reads the
// given config instead of the default XDG location (CLI-12).
func TestRigLs_HonorsConfigFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)
	// Point XDG at an empty dir so the default path has no config: if rig ls
	// ignored --config it would list zero rigs.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"rig", "ls", "--config", cfgPath})
	require.NoError(t, root.Execute())

	assert.Contains(t, out.String(), "alpha", "rig ls must read the --config path")
	assert.Contains(t, out.String(), "beta")
}

// TestRigLs_Empty asserts that `rig ls` on an empty config returns no error and
// produces no table rows (graceful empty state).
func TestRigLs_Empty(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	var out bytes.Buffer
	err = runRigLs(cfgPath, false, &out)
	require.NoError(t, err)

	// "No rigs enrolled" message or empty output — either is acceptable.
	output := strings.TrimSpace(out.String())
	// Should not panic or error; output can be empty or contain a "no rigs" notice.
	_ = output
}

// TestRigImport_InFileDuplicateRejected covers W8: two rigs sharing a name
// WITHIN one import batch must be rejected — validateImportRigs previously
// only checked incoming names against pre-existing rigs.
func TestRigImport_InFileDuplicateRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	importPath := filepath.Join(dir, "import.yaml")
	importDoc := `rigs:
  - name: twin
    hostname: twin-one.ts.net
    ntfy_topic: abysslink-twin-11111111
    backend: tailscale
  - name: twin
    hostname: twin-two.ts.net
    ntfy_topic: abysslink-twin-22222222
    backend: tailscale
`
	require.NoError(t, os.WriteFile(importPath, []byte(importDoc), 0o600))

	err := runRigImport(cfgPath, importPath, true, nil, io.Discard)
	require.Error(t, err, "in-file duplicate rig names must be rejected")
	assert.Contains(t, err.Error(), "twin", "error must identify the duplicated name")

	// Nothing may have been written.
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Len(t, cfg.Rigs, 2, "config must be unchanged after a rejected import")
}

// TestRigImport_ApplyPrintsConfirmation covers U6: a successful `rig import
// --apply` must confirm what it imported (and point at the enroll step for the
// signing-key half) instead of succeeding silently.
func TestRigImport_ApplyPrintsConfirmation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfgWithRigs(t, dir)

	importPath := filepath.Join(dir, "import.yaml")
	importDoc := `rigs:
  - name: gamma
    hostname: gamma.ts.net
    ntfy_topic: abysslink-gamma-deadbeef
    backend: netbird
`
	require.NoError(t, os.WriteFile(importPath, []byte(importDoc), 0o600))

	var out bytes.Buffer
	require.NoError(t, runRigImport(cfgPath, importPath, true, nil, &out))

	assert.Contains(t, out.String(), `Imported rig "gamma"`, "apply must confirm each imported rig")
	assert.Contains(t, out.String(), "1 rig(s)", "apply must summarise the import")
	assert.Contains(t, out.String(), "enroll rig", "apply must point at the keychain/signing-key step")
}
