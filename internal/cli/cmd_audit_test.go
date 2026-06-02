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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSignedLog builds a SignedAudit-backed log at a temp path with n appended
// signed entries and returns the logPath plus the keychain used to sign it.
func newSignedLog(t *testing.T, n int) (logPath string, kc *secrets.MockStore) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "audit.log")
	kc = secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	for i := 0; i < n; i++ {
		var dh [32]byte
		dh[0] = byte(i)
		require.NoError(t, sa.Append(context.Background(), audit.SignInput{Title: "write", DiffHash: dh}, "/tmp/x", false))
	}
	return logPath, kc
}

func TestAuditCmd_Tree(t *testing.T) {
	cmd := newAuditCmd()
	assert.Equal(t, "audit", cmd.Name())
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"verify", "tail", "ls", "export"} {
		assert.True(t, names[want], "missing subcommand %q", want)
	}
}

func TestAuditVerify_Clean(t *testing.T) {
	logPath, kc := newSignedLog(t, 3)
	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	err := runAuditVerify(context.Background(), p, logPath, kc)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Chain OK")
}

func TestAuditVerify_Broken(t *testing.T) {
	logPath, kc := newSignedLog(t, 4)
	// Corrupt the prev_hash at entry index 2 (the 3rd line).
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 4)
	var e map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[2]), &e))
	e["prev_hash"] = "deadbeef"
	mangled, err := json.Marshal(e)
	require.NoError(t, err)
	lines[2] = string(mangled)
	require.NoError(t, os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	err = runAuditVerify(context.Background(), p, logPath, kc)
	var ee *exitError
	require.True(t, errors.As(err, &ee), "expected exitError, got %v", err)
	assert.Equal(t, exitCodeFatal, ee.ExitCode())
	assert.Contains(t, out.String(), "CHAIN BROKEN at entry 2")
}

func TestAuditTail_LastN(t *testing.T) {
	logPath, _ := newSignedLog(t, 5)
	entries, err := audit.ReadLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 5)

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	require.NoError(t, runAuditTail(p, logPath, 2, false))
	// Two rows rendered: count "write" occurrences (Op column).
	assert.Equal(t, 2, strings.Count(out.String(), "write"))
}

func TestAuditTail_JSON(t *testing.T) {
	logPath, _ := newSignedLog(t, 5)
	var out bytes.Buffer
	p := NewJSONPrinterTo(&out, &out)
	require.NoError(t, runAuditTail(p, logPath, 2, true))
	var got []audit.Entry
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Len(t, got, 2)
}

func TestAuditLs_All(t *testing.T) {
	logPath, _ := newSignedLog(t, 3)
	var out bytes.Buffer
	p := NewJSONPrinterTo(&out, &out)
	require.NoError(t, runAuditLs(p, logPath, true))
	var got []audit.Entry
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Len(t, got, 3)
}

func TestAuditExport_JSONL(t *testing.T) {
	logPath, _ := newSignedLog(t, 2)
	var out bytes.Buffer
	require.NoError(t, runAuditExport(&out, logPath))
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	assert.Len(t, lines, 2)
	for _, ln := range lines {
		var e audit.Entry
		assert.NoError(t, json.Unmarshal([]byte(ln), &e))
	}
}

func TestAuditTail_NoLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "missing.log")
	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	require.NoError(t, runAuditTail(p, logPath, 20, false))
	assert.Contains(t, out.String(), "No audit entries found")
}
