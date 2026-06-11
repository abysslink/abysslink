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
	"archive/tar"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompareUpgradeVersions covers W13: the freshness check must be a semver
// comparison, never string equality — a build newer than the latest release
// must be classified as a (refusable) downgrade, not "newer available".
func TestCompareUpgradeVersions(t *testing.T) {
	cases := []struct {
		installed, latest string
		want              int
	}{
		{"v1.2.3", "v1.2.3", upgradeUpToDate},
		{"1.2.3", "v1.2.3", upgradeUpToDate}, // v-prefix normalization
		{"v1.2.3", "v1.2.4", upgradeNewerAvailable},
		{"v1.2.3", "v2.0.0", upgradeNewerAvailable},
		{"v1.3.0", "v1.2.9", upgradeInstalledNewer}, // newer local build → downgrade territory
		{"v2.0.0", "v1.9.9", upgradeInstalledNewer},
		{"dev", "v1.2.3", upgradeUnknownInstalled},
		{"unknown", "v1.2.3", upgradeUnknownInstalled},
	}
	for _, c := range cases {
		got := compareUpgradeVersions(c.installed, c.latest)
		assert.Equal(t, c.want, got, "installed=%s latest=%s", c.installed, c.latest)
	}
}

// TestUpgradeCheckFlagDocumentsExitCode asserts the `upgrade` help documents
// the --check exit-code contract (U9).
func TestUpgradeCheckFlagDocumentsExitCode(t *testing.T) {
	cmd := newUpgradeCmd()
	assert.Contains(t, cmd.Long, "3", "Long help must document the update-available exit code")
	assert.Contains(t, cmd.Long, "newer release is available")
	f := cmd.Flags().Lookup("check")
	require.NotNil(t, f)
	assert.Contains(t, f.Usage, "exit 3", "--check usage must name the distinct exit code")
	require.NotNil(t, cmd.Flags().Lookup("force"), "--force (downgrade override) must be registered")
}

// writeTarGz writes a .tar.gz containing one regular file named "abysslink"
// with the given payload size, returning the archive path.
func writeTarGz(t *testing.T, dir string, payload []byte) string {
	t.Helper()
	tarPath := filepath.Join(dir, "test.tar.gz")
	f, err := os.Create(tarPath) //nolint:gosec // test temp path
	require.NoError(t, err)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "abysslink",
		Mode:     0o755,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}))
	_, err = tw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())
	return tarPath
}

// withArtifactCeiling temporarily lowers the artifact ceiling test seam.
func withArtifactCeiling(t *testing.T, n int64) {
	t.Helper()
	old := upgradeArtifactCeiling
	upgradeArtifactCeiling = n
	t.Cleanup(func() { upgradeArtifactCeiling = old })
}

// TestExtractBinary_OverflowSentinel covers W10: a binary larger than the
// ceiling must FAIL extraction — never be silently truncated and installed as
// a "verified" binary (extraction runs AFTER checksum verification).
func TestExtractBinary_OverflowSentinel(t *testing.T) {
	withArtifactCeiling(t, 64)
	dir := t.TempDir()
	tarPath := writeTarGz(t, dir, make([]byte, 65)) // one byte past the ceiling

	_, err := extractBinary(tarPath, dir)
	require.Error(t, err, "an over-ceiling binary must fail extraction")
	assert.Contains(t, err.Error(), "ceiling", "the error must name the ceiling, not a generic copy failure")
}

// TestExtractBinary_UnderCeilingOK is the happy path under the same seam.
func TestExtractBinary_UnderCeilingOK(t *testing.T) {
	withArtifactCeiling(t, 64)
	dir := t.TempDir()
	payload := []byte("binary-content")
	tarPath := writeTarGz(t, dir, payload)

	outPath, err := extractBinary(tarPath, dir)
	require.NoError(t, err)
	got, err := os.ReadFile(outPath) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, payload, got, "the extracted binary must be byte-complete")
}

// TestDownloadFile_OverflowSentinel covers the download half of W10: an
// over-ceiling response body must error, never be truncated to a "successful"
// partial file.
func TestDownloadFile_OverflowSentinel(t *testing.T) {
	withArtifactCeiling(t, 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 65))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "artifact")
	err := downloadFile(context.Background(), srv.URL, dest)
	require.Error(t, err, "an over-ceiling download must fail")
	assert.Contains(t, err.Error(), "ceiling")
}

// TestDownloadFile_UnderCeilingOK is the happy path under the same seam.
func TestDownloadFile_UnderCeilingOK(t *testing.T) {
	withArtifactCeiling(t, 64)
	body := []byte("artifact-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "artifact")
	require.NoError(t, downloadFile(context.Background(), srv.URL, dest))
	got, err := os.ReadFile(dest) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, body, got)
}
