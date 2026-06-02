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
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionProvenanceDevBuild(t *testing.T) {
	old := slsaURL
	t.Cleanup(func() { slsaURL = old })
	slsaURL = ""

	cmd := newVersionCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	require.NoError(t, cmd.Flags().Set("provenance", "true"))
	require.NoError(t, cmd.RunE(cmd, nil))

	assert.Contains(t, out.String(), "SLSA provenance:")
	assert.Contains(t, out.String(), "(none — dev build)")
}

func TestVersionProvenanceWithURL(t *testing.T) {
	oldS, oldB := slsaURL, bundleURL
	t.Cleanup(func() { slsaURL, bundleURL = oldS, oldB })
	slsaURL = "https://example.com/slsa"
	bundleURL = "https://example.com/bundle"

	cmd := newVersionCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	require.NoError(t, cmd.Flags().Set("provenance", "true"))
	require.NoError(t, cmd.RunE(cmd, nil))

	assert.Contains(t, out.String(), "https://example.com/slsa")
	assert.Contains(t, out.String(), "https://example.com/bundle")
}

func TestVersionProvenanceJSON(t *testing.T) {
	oldS, oldB := slsaURL, bundleURL
	t.Cleanup(func() { slsaURL, bundleURL = oldS, oldB })
	slsaURL = "https://example.com/slsa"
	bundleURL = "https://example.com/bundle"

	cmd := newVersionCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	require.NoError(t, cmd.Flags().Set("provenance", "true"))
	require.NoError(t, cmd.Flags().Set("json", "true"))
	require.NoError(t, cmd.RunE(cmd, nil))

	var rec provenanceJSON
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rec))
	assert.Equal(t, "https://example.com/slsa", rec.SLSAURL)
	assert.Equal(t, "https://example.com/bundle", rec.BundleURL)
	assert.Equal(t, version, rec.Version)
}

// supplyDoctorFixture writes a checksums + bundle pair so the cosign bundle check
// skips all network downloads. Returns the bundle path.
func supplyDoctorFixture(t *testing.T, ver string) string {
	t.Helper()
	dir := t.TempDir()
	checksumName := "abysslink_" + ver + "_checksums.txt"
	require.NoError(t, os.WriteFile(filepath.Join(dir, checksumName), []byte("deadbeef  x.tar.gz\n"), 0o600))
	bundlePath := filepath.Join(dir, checksumName+".bundle")
	require.NoError(t, os.WriteFile(bundlePath, []byte("{}"), 0o600))
	return bundlePath
}

func findFinding(findings []modules.Finding, check string) (modules.Finding, bool) {
	for _, f := range findings {
		if f.Check == check {
			return f, true
		}
	}
	return modules.Finding{}, false
}

func TestDoctorSupplyCosignBundleOK(t *testing.T) {
	bundlePath := supplyDoctorFixture(t, "9.9.9")
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})

	findings := supplyChainFindings(context.Background(), runner, "9.9.9", bundlePath)
	got, ok := findFinding(findings, "supply-cosign-bundle")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, got.Severity)
}

func TestDoctorSupplyCosignBundleFail(t *testing.T) {
	bundlePath := supplyDoctorFixture(t, "9.9.9")
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "bad"}})

	findings := supplyChainFindings(context.Background(), runner, "9.9.9", bundlePath)
	got, ok := findFinding(findings, "supply-cosign-bundle")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, got.Severity)
}

func TestDoctorSupplySLSASourceEmpty(t *testing.T) {
	old := slsaURL
	t.Cleanup(func() { slsaURL = old })
	slsaURL = ""

	bundlePath := supplyDoctorFixture(t, "9.9.9")
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
	findings := supplyChainFindings(context.Background(), runner, "9.9.9", bundlePath)

	got, ok := findFinding(findings, "supply-slsa-source")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, got.Severity)
}
