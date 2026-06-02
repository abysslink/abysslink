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
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupVerifyFixture creates a temp dir holding a checksums file and returns the
// bundle path (a sibling file so runVerify skips all network downloads) plus the
// version string the test should pass.
func setupVerifyFixture(t *testing.T, ver string) (bundlePath string) {
	t.Helper()
	dir := t.TempDir()
	checksumName := "abysslink_" + ver + "_checksums.txt"
	require.NoError(t, os.WriteFile(filepath.Join(dir, checksumName), []byte("deadbeef  abysslink.tar.gz\n"), 0o600))
	bundlePath = filepath.Join(dir, checksumName+".bundle")
	require.NoError(t, os.WriteFile(bundlePath, []byte("{}"), 0o600))
	return bundlePath
}

func TestVerifyBundleOK(t *testing.T) {
	bundlePath := setupVerifyFixture(t, "9.9.9")
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "Verified OK"}})

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	err := runVerify(context.Background(), p, runner, verifyOpts{
		version:        "9.9.9",
		bundleOverride: bundlePath,
	})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "cosign bundle verified")
}

func TestVerifyBundleFail(t *testing.T) {
	bundlePath := setupVerifyFixture(t, "9.9.9")
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "error: bundle invalid"}})

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	err := runVerify(context.Background(), p, runner, verifyOpts{
		version:        "9.9.9",
		bundleOverride: bundlePath,
	})
	require.Error(t, err)
	assert.Contains(t, out.String(), "FAILED")
}

func TestVerifyNoCosign(t *testing.T) {
	bundlePath := setupVerifyFixture(t, "9.9.9")
	// A runner that returns an exec error simulates cosign not being on PATH.
	runner := shell.NewMockRunner(shell.Call{Err: errors.New("exec: \"cosign\": executable file not found in $PATH")})

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	err := runVerify(context.Background(), p, runner, verifyOpts{
		version:        "9.9.9",
		bundleOverride: bundlePath,
	})
	require.Error(t, err)
	assert.Contains(t, out.String(), "cosign not found")
}

func TestVerifyJSON(t *testing.T) {
	bundlePath := setupVerifyFixture(t, "9.9.9")
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "Verified OK"}})

	var out bytes.Buffer
	p := NewJSONPrinterTo(&out, &out)
	err := runVerify(context.Background(), p, runner, verifyOpts{
		version:        "9.9.9",
		bundleOverride: bundlePath,
		jsonOut:        true,
	})
	require.NoError(t, err)

	var res verifyResult
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out.Bytes()), &res))
	assert.True(t, res.BundleOK)
	assert.Equal(t, "9.9.9", res.Version)
}

// TestVerifyCosignBundleArgs asserts the v3 bundle args are passed to cosign:
// --bundle and --offline (not the v2 --certificate/--signature pair).
func TestVerifyCosignBundleArgs(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
	err := verifyCosignBundle(context.Background(), runner, "checksums.txt", "checksums.txt.bundle")
	require.NoError(t, err)

	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "cosign", calls[0].Name)
	assert.Contains(t, calls[0].Args, "--bundle")
	assert.Contains(t, calls[0].Args, "--offline")
	assert.NotContains(t, calls[0].Args, "--certificate")
	assert.NotContains(t, calls[0].Args, "--signature")
}

// TestUpgradeVerifyCosignBlobV3 asserts the upgrade path delegates to the v3
// bundle verifier with --bundle (single bundleFile parameter).
func TestUpgradeVerifyCosignBlobV3(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
	err := verifyCosignBlob(context.Background(), runner, "checksums.txt", "checksums.txt.bundle")
	require.NoError(t, err)

	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].Args, "--bundle")
	assert.Contains(t, calls[0].Args, "--offline")
}
