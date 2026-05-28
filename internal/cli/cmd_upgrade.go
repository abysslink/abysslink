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

	"github.com/spf13/cobra"
)

const (
	upgradeRepo           = "abysslink/abysslink"
	upgradeOIDCIssuer     = "https://token.actions.githubusercontent.com"
	upgradeIdentityRegexp = "https://github.com/abysslink/abysslink/.github/workflows/release.yml@refs/tags/.*"
)

func newUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade abysslink to the latest release",
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
			return applyUpgrade(c.Context(), p, latest)
		},
	}
	cmd.Flags().Bool("check", false, "Only check for a newer version, do not upgrade")
	cmd.Flags().Bool("apply", false, "Download, verify signature, and self-replace the binary")
	return cmd
}

// applyUpgrade downloads the release for the current OS/arch, verifies its
// cosign signature, checks SHA-256 integrity, and performs an atomic
// self-replace of the running binary.
func applyUpgrade(ctx context.Context, p Printer, tag string) error {
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

	// Download all artifacts.
	for _, name := range []string{tarball, checksums, checksums + ".sig", checksums + ".pem"} {
		printerInfo(p, "  ↓  "+name)
		if err := downloadFile(ctx, baseURL+"/"+name, filepath.Join(tmpDir, name)); err != nil {
			return fmt.Errorf("upgrade: download %s: %w", name, err)
		}
	}

	// Verify cosign signature on the checksum manifest.
	printerInfo(p, "  ✦  verifying cosign signature...")
	if err := verifyCosignBlob(ctx,
		filepath.Join(tmpDir, checksums),
		filepath.Join(tmpDir, checksums+".sig"),
		filepath.Join(tmpDir, checksums+".pem"),
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
	if err := atomicReplace(selfPath, newBin); err != nil {
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

// verifyCosignBlob verifies the cosign keyless signature on target using the
// provided .sig and .pem files from the release.
func verifyCosignBlob(ctx context.Context, target, sigFile, certFile string) error {
	cmd := exec.CommandContext(ctx, "cosign", "verify-blob", //nolint:gosec
		"--certificate", certFile,
		"--signature", sigFile,
		"--certificate-identity-regexp", upgradeIdentityRegexp,
		"--certificate-oidc-issuer", upgradeOIDCIssuer,
		target,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cosign verify-blob: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifyChecksum reads the sha256 checksum file and checks that the file at
// filePath matches the recorded hash for wantName.
func verifyChecksum(checksumFile, wantName, filePath string) error {
	f, err := os.Open(checksumFile) //nolint:gosec
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
	// Shell out to avoid adding crypto/sha256 import in this file.
	// Use a pure-Go approach instead.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// extractBinary extracts the `abysslink` binary from a .tar.gz archive to outDir.
func extractBinary(tarPath, outDir string) (string, error) {
	f, err := os.Open(tarPath) //nolint:gosec
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
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) //nolint:gosec
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, 200<<20)); err != nil { //nolint:gosec
			_ = out.Close()
			return "", err
		}
		_ = out.Close()
		return outPath, nil
	}
	return "", fmt.Errorf("abysslink binary not found in archive")
}

// atomicReplace replaces dst with src using a write-to-temp + rename pattern
// to ensure the process is never in a half-replaced state.
func atomicReplace(dst, src string) error {
	dstDir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dstDir, ".abysslink-upgrade-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	srcData, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, srcData, 0o755); err != nil { //nolint:gosec
		return err
	}
	return os.Rename(tmpPath, dst)
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	f, err := os.Create(dest) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, io.LimitReader(resp.Body, 200<<20)) //nolint:gosec
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("no tag_name in latest release")
	}
	return rel.TagName, nil
}

// normalizeTag strips a leading "v" so "v1.2.3" and "1.2.3" compare equal.
func normalizeTag(t string) string { return strings.TrimPrefix(strings.TrimSpace(t), "v") }
