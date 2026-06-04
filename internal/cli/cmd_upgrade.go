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
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/limitio"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

const (
	upgradeRepo           = "abysslink/abysslink"
	upgradeOIDCIssuer     = "https://token.actions.githubusercontent.com"
	upgradeIdentityRegexp = `^https://github\.com/abysslink/abysslink/\.github/workflows/release\.yml@refs/tags/.*$`
)

func newUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade abysslink to the latest release",
		Example: `  # Preview the upgrade (dry-run — no changes)
  abysslink upgrade

  # Download and install the latest release
  abysslink upgrade --apply`,
		RunE: func(c *cobra.Command, _ []string) error {
			if os.Getuid() == 0 {
				return fmt.Errorf("upgrade: refusing to run as root — run as your normal user")
			}

			checkOnly, _ := c.Flags().GetBool("check")
			apply, _ := c.Flags().GetBool("apply")
			p := newPrinter(c)

			latest, err := latestReleaseTag(c.Context())
			if err != nil {
				return fmt.Errorf("upgrade: check latest release: %w", err)
			}
			printerInfo(p, fmt.Sprintf("Installed: %s   Latest: %s", version, latest))
			if normalizeTag(latest) == normalizeTag(version) {
				printerInfo(p, styleSuccess.Render("Already up to date."))
				return nil
			}
			printerInfo(p, styleWarn.Render("A newer release is available."))

			if checkOnly {
				return nil
			}

			if !apply {
				printerInfo(p, "")
				printerInfo(p, "Run "+styleCode.Render("abysslink upgrade --apply")+" to self-update.")
				printerInfo(p, "Or use a trusted install path:")
				printerInfo(p, "  • "+styleCode.Render("curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | bash"))
				printerInfo(p, "  • your package manager (brew / apt / dnf)")
				return nil
			}

			// --apply path: download → verify cosign → verify checksum → self-replace.
			return applyUpgrade(c.Context(), p, &shell.ExecRunner{}, latest)
		},
	}
	cmd.Flags().Bool("check", false, "Only check for a newer version, do not upgrade")
	cmd.Flags().Bool("apply", false, "Download, verify signature, and self-replace the binary")
	return cmd
}

// applyUpgrade downloads the release for the current OS/arch, verifies its
// cosign signature, checks SHA-256 integrity, and performs an atomic
// self-replace of the running binary.
func applyUpgrade(ctx context.Context, p Printer, runner shell.Runner, tag string) error {
	if err := checkCosignInstalled(); err != nil {
		return err
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("upgrade: resolve self path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("upgrade: resolve symlinks: %w", err)
	}

	ver := strings.TrimPrefix(tag, "v")
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	tarball := fmt.Sprintf("abysslink_%s_%s_%s.tar.gz", ver, goos, goarch)
	checksums := fmt.Sprintf("abysslink_%s_checksums.txt", ver)
	baseURL := fmt.Sprintf("https://github.com/%s/releases/download/%s", upgradeRepo, tag)

	tmpDir, err := os.MkdirTemp("", "abysslink-upgrade-*")
	if err != nil {
		return fmt.Errorf("upgrade: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Download all artifacts. The cosign v3 bundle embeds both the signature and
	// the signing certificate, so a single .bundle file replaces the v2 .sig/.pem pair.
	for _, name := range []string{tarball, checksums, checksums + ".bundle"} {
		printerInfo(p, "  ↓  "+name)
		if err := downloadFile(ctx, baseURL+"/"+name, filepath.Join(tmpDir, name)); err != nil {
			return fmt.Errorf("upgrade: download %s: %w", name, err)
		}
	}

	// Verify cosign v3 bundle signature on the checksum manifest (offline — no Rekor).
	printerInfo(p, "  ✦  verifying cosign signature...")
	if err := verifyCosignBlob(ctx, runner,
		filepath.Join(tmpDir, checksums),
		filepath.Join(tmpDir, checksums+".bundle"),
	); err != nil {
		return fmt.Errorf("upgrade: cosign verification FAILED — refusing to install: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  signature verified"))

	// Verify tarball SHA-256 against the signed checksum manifest.
	printerInfo(p, "  ✦  verifying checksum...")
	if err := verifyChecksum(filepath.Join(tmpDir, checksums), tarball, filepath.Join(tmpDir, tarball)); err != nil {
		return fmt.Errorf("upgrade: checksum verification FAILED: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  checksum verified"))

	// Extract binary from tarball.
	newBin, err := extractBinary(filepath.Join(tmpDir, tarball), tmpDir)
	if err != nil {
		return fmt.Errorf("upgrade: extract binary: %w", err)
	}

	// Atomic self-replace.
	printerInfo(p, "  ↺  replacing "+selfPath)
	if err := atomicReplace(ctx, selfPath, newBin); err != nil {
		return fmt.Errorf("upgrade: self-replace: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  upgraded to "+tag))
	printerInfo(p, "  Run "+styleCode.Render("abysslink version")+" to confirm.")
	return nil
}

// checkCosignInstalled returns an error with install guidance if cosign is absent.
func checkCosignInstalled() error {
	if _, err := exec.LookPath("cosign"); err != nil {
		return fmt.Errorf("upgrade: cosign not found — install it first:\n" +
			"  https://docs.sigstore.dev/cosign/system_config/installation/\n" +
			"  brew install cosign   (macOS)\n" +
			"  go install github.com/sigstore/cosign/v2/cmd/cosign@latest")
	}
	return nil
}

// verifyCosignBlob verifies the cosign v3 keyless signature on target using the
// provided .bundle file from the release. The bundle embeds the signature and
// signing certificate, so no separate .sig/.pem files are needed. It delegates
// to verifyCosignBundle, which runs cosign in --offline mode (no Rekor lookup).
func verifyCosignBlob(ctx context.Context, runner shell.Runner, target, bundleFile string) error {
	return verifyCosignBundle(ctx, runner, target, bundleFile)
}

// verifyChecksum reads the sha256 checksum file and checks that the file at
// filePath matches the recorded hash for wantName.
func verifyChecksum(checksumFile, wantName, filePath string) error {
	f, err := os.Open(checksumFile) //nolint:gosec // G304: checksumFile is an internally-staged download temp path, not user input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		want, name := parts[0], parts[1]
		if strings.TrimPrefix(name, "*") != wantName {
			continue
		}
		got, err := sha256File(filePath)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("SHA-256 mismatch for %s: got %s want %s", wantName, got, want)
		}
		return nil
	}
	return fmt.Errorf("no checksum entry found for %s in %s", wantName, checksumFile)
}

// sha256File returns the lower-hex SHA-256 of a file.
func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is an internally-staged download temp path, not user input
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// extractBinary extracts the `abysslink` binary from a .tar.gz archive to outDir.
func extractBinary(tarPath, outDir string) (string, error) {
	f, err := os.Open(tarPath) //nolint:gosec // G304: tarPath is an internally-staged download temp path, not user input
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if base != "abysslink" && base != "abysslink.exe" {
			continue
		}
		outPath := filepath.Join(outDir, base)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) //nolint:gosec // G302: 0o755 required — extracted file is an executable binary
		if err != nil {
			return "", err
		}
		// nosemgrep: go.lang.security.decompression_bomb.potential-dos-via-decompression-bomb
		if _, err := io.Copy(out, io.LimitReader(tr, 200<<20)); err != nil { //nolint:gosec // G110: io.LimitReader caps extraction at 200MiB — decompression bomb mitigated
			_ = out.Close()
			return "", err
		}
		_ = out.Close()
		return outPath, nil
	}
	return "", fmt.Errorf("abysslink binary not found in archive")
}

// atomicReplace replaces dst with src via audit.WriteFilePath — streaming
// io.Copy with a 256 MiB ceiling (D-06 / WR-02). WriteFilePath handles temp
// creation, chmod, and atomic rename; the binary is never fully in memory.
// Per CLAUDE.md hard rule: every file mutation goes through internal/audit.
// The keychain store uses shell.ExecRunner — keychain operations are always
// real system calls and must never be routed through the CLI mock runner.
func atomicReplace(ctx context.Context, dst, src string) error {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("atomicReplace: audit log path: %w", err)
	}
	kc, err := secrets.NewStore(ctx, &shell.ExecRunner{})
	if err != nil {
		return fmt.Errorf("atomicReplace: keychain: %w", err)
	}
	sa, err := audit.NewSigned(logPath, kc)
	if err != nil {
		return fmt.Errorf("atomicReplace: audit init: %w", err)
	}
	if err := sa.WriteFilePath(ctx, src, dst, 0o755, false); err != nil {
		return fmt.Errorf("atomicReplace: write: %w", err)
	}
	return nil
}

// downloadFile downloads url to dest, following redirects.
func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(limitio.ReadSnippet(resp.Body)))
	}
	f, err := os.Create(dest) //nolint:gosec // G304: dest is an internally-derived download temp path, not user input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, io.LimitReader(resp.Body, 200<<20)) //nolint:gosec // G110: io.LimitReader caps download at 200MiB — decompression/oversize bomb mitigated
	return err
}

// latestReleaseTag returns the tag_name of the latest GitHub release.
func latestReleaseTag(ctx context.Context) (string, error) {
	const url = "https://api.github.com/repos/abysslink/abysslink/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, strings.TrimSpace(limitio.ReadSnippet(resp.Body)))
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	relData, err := limitio.ReadLimited(resp.Body, limitio.MaxBackendBody)
	if err != nil {
		return "", fmt.Errorf("GitHub releases: read response: %w", err)
	}
	if err := json.Unmarshal(relData, &rel); err != nil {
		return "", fmt.Errorf("GitHub releases: decode response: %w", err)
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("no tag_name in latest release")
	}
	return rel.TagName, nil
}

// normalizeTag strips a leading "v" so "v1.2.3" and "1.2.3" compare equal.
func normalizeTag(t string) string { return strings.TrimPrefix(strings.TrimSpace(t), "v") }
