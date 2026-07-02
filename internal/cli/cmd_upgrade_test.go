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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/shell"
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
		// finding [27]: an rc install must be able to upgrade to the same-version
		// final release (SemVer: 4.1.0-rc.1 < 4.1.0), not be told "up to date".
		{"v4.1.0-rc.1", "v4.1.0", upgradeNewerAvailable},
		{"v4.1.0-beta.2", "v4.1.0", upgradeNewerAvailable},
		// A final release is newer than a same-version pre-release.
		{"v4.1.0", "v4.1.0-rc.1", upgradeInstalledNewer},
		// git-describe `make build` binaries are non-release → unknown, never
		// "already up to date" (contradicted the func's own doc).
		{"v3.0.2-16-g10e83c2", "v3.0.2", upgradeUnknownInstalled},
		{"3.0.2-16-g10e83c2-dirty", "v3.0.2", upgradeUnknownInstalled},
		// Two differing pre-release suffixes on the same version stay up-to-date
		// (not confidently orderable → no flapping).
		{"v4.1.0-rc.1", "v4.1.0-rc.2", upgradeUpToDate},
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

// TestVerifyUpgradeArtifact_ProvenanceFailAborts covers the fail-closed
// contract on the upgrade --apply path: when cosign passes but the SLSA
// provenance leg (`gh attestation verify`) fails, verifyUpgradeArtifact must
// return an error so the caller never reaches the atomic-replace step. The
// MockRunner scripts cosign exit 0 then gh exit 1.
func TestVerifyUpgradeArtifact_ProvenanceFailAborts(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "Verified OK"}},           // cosign
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "no attestations found"}}, // gh attestation verify
	)
	err := verifyUpgradeArtifact(context.Background(), runner,
		"checksums.txt", "checksums.txt.bundle", "abysslink_1.2.3_linux_amd64.tar.gz")
	require.Error(t, err, "a provenance failure must abort the upgrade before install")
	assert.Contains(t, err.Error(), "provenance")

	calls := runner.RecordedCalls()
	require.Len(t, calls, 2, "both cosign and gh must have been invoked")
	assert.Equal(t, "cosign", calls[0].Name)
	assert.Equal(t, "gh", calls[1].Name)
}

// TestVerifyUpgradeArtifact_NoGHAborts covers the gh-absent fail-closed
// decision on the upgrade path (Open Question 2).
func TestVerifyUpgradeArtifact_NoGHAborts(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "Verified OK"}}, // cosign
		shell.Call{Err: errors.New(`exec: "gh": executable file not found in $PATH`)},
	)
	err := verifyUpgradeArtifact(context.Background(), runner,
		"checksums.txt", "checksums.txt.bundle", "abysslink_1.2.3_linux_amd64.tar.gz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gh not found")
}

// TestVerifyUpgradeArtifact_AllOK is the happy path: cosign + provenance both
// pass, no error.
func TestVerifyUpgradeArtifact_AllOK(t *testing.T) {
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "Verified OK"}},
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "Verification succeeded!"}},
	)
	err := verifyUpgradeArtifact(context.Background(), runner,
		"checksums.txt", "checksums.txt.bundle", "abysslink_1.2.3_linux_amd64.tar.gz")
	require.NoError(t, err)
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

// ── finding [17]: co-installed abysslinkd is upgraded in lockstep ────────────

// writeTarGzFiles writes a .tar.gz containing the given name→payload regular
// files, returning the archive path.
func writeTarGzFiles(t *testing.T, dir string, files map[string][]byte) string {
	t.Helper()
	tarPath := filepath.Join(dir, "multi.tar.gz")
	f, err := os.Create(tarPath) //nolint:gosec // test temp path
	require.NoError(t, err)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, payload := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(payload)),
			Typeflag: tar.TypeReg,
		}))
		_, err = tw.Write(payload)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())
	return tarPath
}

// newMockSignedAudit builds a SignedAudit backed by a mock keychain + temp log so
// the atomic-replace path is exercisable on platforms without a real keychain
// backend (Linux CI has no libsecret/secret-tool).
func newMockSignedAudit(t *testing.T, dir string) *audit.SignedAudit {
	t.Helper()
	mockKC := &mockKeychainStore{entries: map[string]string{}}
	sa, err := audit.NewSigned(filepath.Join(dir, "audit.log"), mockKC)
	require.NoError(t, err)
	return sa
}

// TestExtractNamedBinary_PicksExactBinary verifies the generalized extractor
// selects the requested binary and never confuses abysslink with abysslinkd.
func TestExtractNamedBinary_PicksExactBinary(t *testing.T) {
	dir := t.TempDir()
	tarPath := writeTarGzFiles(t, dir, map[string][]byte{
		"abysslink":  []byte("CLI-payload"),
		"abysslinkd": []byte("DAEMON-payload"),
	})

	outCLI, err := extractNamedBinary(tarPath, dir, "abysslink")
	require.NoError(t, err)
	got, err := os.ReadFile(outCLI) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, "CLI-payload", string(got), "extracting abysslink must not pick up abysslinkd")

	outDaemon, err := extractNamedBinary(tarPath, dir, "abysslinkd")
	require.NoError(t, err)
	got, err = os.ReadFile(outDaemon) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, "DAEMON-payload", string(got), "extracting abysslinkd must yield the daemon binary")
}

// TestUpgradeSiblingDaemon_ReplacesCoInstalledDaemon covers the core of finding
// [17]: a stale abysslinkd next to the CLI is atomically replaced with the
// tarball's daemon binary so daemon-side security fixes actually land.
func TestUpgradeSiblingDaemon_ReplacesCoInstalledDaemon(t *testing.T) {
	dir := t.TempDir()
	cliPath := filepath.Join(dir, "abysslink")
	require.NoError(t, os.WriteFile(cliPath, []byte("cli"), 0o755)) //nolint:gosec // test binary perms
	daemonPath := filepath.Join(dir, "abysslinkd")
	require.NoError(t, os.WriteFile(daemonPath, []byte("STALE-daemon"), 0o755)) //nolint:gosec // test binary perms

	tmpDir := t.TempDir()
	tarPath := writeTarGzFiles(t, tmpDir, map[string][]byte{
		"abysslink":  []byte("new-cli"),
		"abysslinkd": []byte("NEW-daemon"),
	})

	replaced, err := upgradeSiblingDaemon(context.Background(), newMockSignedAudit(t, dir), cliPath, tarPath, tmpDir)
	require.NoError(t, err)
	assert.True(t, replaced, "a co-installed daemon must be replaced")

	got, err := os.ReadFile(daemonPath) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Equal(t, "NEW-daemon", string(got), "the stale daemon must be overwritten with the tarball's daemon")
}

// TestUpgradeSiblingDaemon_NoSiblingIsNoop verifies that with no co-installed
// daemon the function is a clean no-op (the common single-binary CLI install).
func TestUpgradeSiblingDaemon_NoSiblingIsNoop(t *testing.T) {
	dir := t.TempDir()
	cliPath := filepath.Join(dir, "abysslink")
	require.NoError(t, os.WriteFile(cliPath, []byte("cli"), 0o755)) //nolint:gosec // test binary perms

	tmpDir := t.TempDir()
	tarPath := writeTarGzFiles(t, tmpDir, map[string][]byte{"abysslinkd": []byte("NEW")})

	replaced, err := upgradeSiblingDaemon(context.Background(), newMockSignedAudit(t, dir), cliPath, tarPath, tmpDir)
	require.NoError(t, err)
	assert.False(t, replaced, "no co-installed daemon → no-op")
}

// TestUpgradeSiblingDaemon_TarballMissingDaemon_Errors verifies the skew-warning
// path: a co-installed daemon plus a tarball with no daemon binary surfaces an
// error so the caller can warn the daemon is now version-skewed.
func TestUpgradeSiblingDaemon_TarballMissingDaemon_Errors(t *testing.T) {
	dir := t.TempDir()
	cliPath := filepath.Join(dir, "abysslink")
	require.NoError(t, os.WriteFile(cliPath, []byte("cli"), 0o755))                            //nolint:gosec // test binary perms
	require.NoError(t, os.WriteFile(filepath.Join(dir, "abysslinkd"), []byte("stale"), 0o755)) //nolint:gosec // test binary perms

	tmpDir := t.TempDir()
	tarPath := writeTarGzFiles(t, tmpDir, map[string][]byte{"abysslink": []byte("new-cli")}) // no daemon

	replaced, err := upgradeSiblingDaemon(context.Background(), newMockSignedAudit(t, dir), cliPath, tarPath, tmpDir)
	require.Error(t, err, "a tarball without the daemon binary must surface an error")
	assert.False(t, replaced)
	assert.Contains(t, err.Error(), "not in release archive")
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
