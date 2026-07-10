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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedAuditLog redirects the audit log into a temp XDG_STATE_HOME and appends
// the given entries via the unsigned writer. Under `go test`,
// openPlatformKeychain returns (nil,nil) so the real keychain is never touched.
func seedAuditLog(t *testing.T, entries ...audit.Entry) string {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	logPath, err := audit.DefaultLogPath()
	require.NoError(t, err)
	w := audit.New(logPath)
	for _, e := range entries {
		require.NoError(t, w.Append(e.Op, e.Target, nil, e.DryRun))
	}
	return logPath
}

// runDiaryCLI executes the diary command end-to-end and returns captured stdout.
func runDiaryCLI(t *testing.T, args ...string) string {
	t.Helper()
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	require.NoError(t, root.Execute())
	return out.String()
}

// diaryJSONObject runs `--json diary ...` and unmarshals the single object.
func diaryJSONObject(t *testing.T, args ...string) map[string]any {
	t.Helper()
	out := runDiaryCLI(t, args...)
	line := strings.TrimSpace(out)
	require.NotEmpty(t, line, "expected a JSON object on stdout")
	var obj map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &obj), "output: %q", out)
	return obj
}

func TestDiaryJSON_Counts(t *testing.T) {
	// All entries are appended "now"; seed and query today so the window matches.
	seedAuditLog(t,
		audit.Entry{Op: "wol", Target: "rig-1/aa:bb:cc:dd:ee:ff"},
		audit.Entry{Op: "arm-run:end", Target: "/casts/run.cast"},
		audit.Entry{Op: "approve-decision", Target: "request:abc"},
		audit.Entry{Op: "ack-receipt", Target: "device:phone"},
		audit.Entry{Op: "write", Target: "/cfg/a.yaml", DryRun: true},
		audit.Entry{Op: "backup", Target: "/cfg/a.yaml.bak"},
	)

	obj := diaryJSONObject(t, "--json", "diary")

	assert.Equal(t, float64(6), obj["total_entries"])
	assert.Equal(t, float64(5), obj["applied"])
	assert.Equal(t, float64(1), obj["dry_run"])
	assert.Equal(t, float64(2), obj["human_gate_events"]) // approval + ack-receipt

	// casts derives only from arm-run:end targets
	casts, ok := obj["casts"].([]any)
	require.True(t, ok)
	require.Len(t, casts, 1)
	assert.Equal(t, "/casts/run.cast", casts[0])

	// per-category counts
	cats, ok := obj["categories"].([]any)
	require.True(t, ok)
	counts := map[string]float64{}
	for _, c := range cats {
		m := c.(map[string]any)
		counts[m["category"].(string)] = m["count"].(float64)
	}
	assert.Equal(t, float64(2), counts["action-run"]) // wol + arm-run:end
	assert.Equal(t, float64(1), counts["approval"])
	assert.Equal(t, float64(1), counts["agent-waited-on-human"])
	assert.Equal(t, float64(1), counts["config-mutation"])
	assert.Equal(t, float64(1), counts["backup"])
	// the 8 known categories always present (zeros included), no "other"
	assert.Len(t, cats, 8)
}

func TestDiaryJSON_ByteStable(t *testing.T) {
	seedAuditLog(t,
		audit.Entry{Op: "wol", Target: "rig-1/aa:bb"},
		audit.Entry{Op: "approve-decision", Target: "request:x"},
		audit.Entry{Op: "write", Target: "/cfg/a.yaml", DryRun: true},
		audit.Entry{Op: "arm-run:end", Target: "/casts/a.cast"},
	)

	out1 := runDiaryCLI(t, "--json", "diary")
	out2 := runDiaryCLI(t, "--json", "diary")
	assert.Equal(t, out1, out2, "running --json diary twice must produce identical bytes")
	// the object carries no wall-clock field
	assert.NotContains(t, out1, "generated_at")
}

func TestDiary_DateFilter(t *testing.T) {
	// Seed today, then confirm a different (past) --date isolates it to an empty
	// digest while today shows the entries.
	seedAuditLog(t, audit.Entry{Op: "wol", Target: "rig/aa:bb"})

	today := diaryJSONObject(t, "--json", "diary")
	assert.Equal(t, float64(1), today["total_entries"])

	past := diaryJSONObject(t, "--json", "diary", "--date", "2000-01-01")
	assert.Equal(t, float64(0), past["total_entries"], "a day with no entries must be a zero digest")
	assert.Equal(t, "2000-01-01", past["date"])
}

func TestDiary_EmptyDay_MissingLog(t *testing.T) {
	// No seeding at all: the audit log file does not exist. This must be a clean
	// zero digest, not an error.
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	obj := diaryJSONObject(t, "--json", "diary")
	assert.Equal(t, float64(0), obj["total_entries"])
	// non-nil empty slices
	notable, ok := obj["notable"].([]any)
	require.True(t, ok, "notable must be [] not null")
	assert.Empty(t, notable)
	casts, ok := obj["casts"].([]any)
	require.True(t, ok, "casts must be [] not null")
	assert.Empty(t, casts)

	// human mode shows the honest no-activity line and still exits 0
	human := runDiaryCLI(t, "diary")
	assert.Contains(t, human, "no recorded activity")
}

func TestDiaryJSON_NoSecretFields(t *testing.T) {
	seedAuditLog(t, audit.Entry{Op: "wol", Target: "rig/aa:bb"})

	// Grab the seeded entry's Hash so we can assert it never appears in output.
	logPath, err := audit.DefaultLogPath()
	require.NoError(t, err)
	entries, err := audit.ReadLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NotEmpty(t, entries[0].Hash)

	out := runDiaryCLI(t, "--json", "diary")

	// projection drops all chain digests
	for _, k := range []string{"\"hash\"", "\"sig\"", "\"prev_hash\"", "\"key_epoch\""} {
		assert.NotContainsf(t, out, k, "diary --json must not emit %s", k)
	}
	// the concrete digest value must be absent
	assert.NotContains(t, out, entries[0].Hash, "the seeded entry's Hash must never appear in the diary")
}

func TestDiary_SecretShapedTargetRedacted(t *testing.T) {
	// A contrived op whose Target is secret-shaped (defense-in-depth). Build the
	// token at runtime so no key-shaped literal sits in source.
	secret := "sk-" + "ant-DEADBEEFdeadbeef0123456789abcdef"
	seedAuditLog(t, audit.Entry{Op: "some-future-op", Target: secret})

	jsonOut := runDiaryCLI(t, "--json", "diary")
	assert.NotContains(t, jsonOut, secret, "raw secret-shaped target must be absent from --json")
	assert.Contains(t, jsonOut, "<redacted:secret-shaped-target>")

	human := runDiaryCLI(t, "diary")
	assert.NotContains(t, human, secret, "raw secret-shaped target must be absent from human output")
	assert.Contains(t, human, "<redacted:secret-shaped-target>")
}

func TestDiary_ReadOnly(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)
	logPath, err := audit.DefaultLogPath()
	require.NoError(t, err)
	require.NoError(t, audit.New(logPath).Append("wol", "rig/aa:bb", nil, false))

	before, err := os.ReadFile(logPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	fiBefore, err := os.Stat(logPath)
	require.NoError(t, err)

	// snapshot the state dir listing
	entriesBefore, err := os.ReadDir(stateDir + "/abysslink")
	require.NoError(t, err)

	_ = runDiaryCLI(t, "diary")
	_ = runDiaryCLI(t, "--json", "diary")

	after, err := os.ReadFile(logPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	fiAfter, err := os.Stat(logPath)
	require.NoError(t, err)

	assert.Equal(t, before, after, "diary must not modify the audit log bytes")
	assert.Equal(t, fiBefore.ModTime(), fiAfter.ModTime(), "diary must not touch the audit log mtime")

	entriesAfter, err := os.ReadDir(stateDir + "/abysslink")
	require.NoError(t, err)
	assert.Equal(t, len(entriesBefore), len(entriesAfter), "diary must not create new files in the state dir")
}

func TestNewDiaryCmdRegistered(t *testing.T) {
	root := buildRootCmd()
	var diaryCmd = func() bool {
		for _, c := range root.Commands() {
			if c.Name() == "diary" {
				assert.Equal(t, "ops", c.GroupID, "diary must be in the ops group")
				_, err := c.Flags().GetString("date")
				assert.NoError(t, err, "diary must define a --date flag")
				return true
			}
		}
		return false
	}()
	assert.True(t, diaryCmd, "buildRootCmd must register the diary command")

	// direct unit sanity on the constructor
	cmd := newDiaryCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "diary", cmd.Name())
	date, err := cmd.Flags().GetString("date")
	require.NoError(t, err)
	assert.Equal(t, "", date)
}

func TestDiaryHuman_ShowsZeroRowsAndCasts(t *testing.T) {
	seedAuditLog(t,
		audit.Entry{Op: "deadman-lockdown", Target: "no operator contact for 24h0m0s"},
		audit.Entry{Op: "arm-run:end", Target: "/casts/run.cast"},
	)

	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)
	logPath, err := audit.DefaultLogPath()
	require.NoError(t, err)
	entries, err := audit.ReadLog(logPath)
	require.NoError(t, err)
	d := digest.Compute(entries, digest.TodayWindow(time.Now()))
	printDiaryHuman(p, d)

	out := buf.String()
	// zero rows are shown (reassurance)
	assert.Contains(t, out, "kill-switch")
	assert.Contains(t, out, "rotations")
	// notable shows the deadman event with time+op+target only
	assert.Contains(t, out, "deadman-lockdown")
	assert.Contains(t, out, "no operator contact for 24h0m0s")
	// casts labelled with provenance
	assert.Contains(t, out, "(from arm-run:end)")
	assert.Contains(t, out, "/casts/run.cast")
}
