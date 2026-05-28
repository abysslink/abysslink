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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
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

			// Self-replace is intentionally NOT performed: abysslink will not
			// overwrite its own binary without verifying a cryptographic
			// signature on the downloaded artifact, and signed releases are not
			// yet published. Installing an unverified binary would be a
			// supply-chain risk, so we fail closed and direct the user to a
			// trusted install path.
			printerInfo(p, "")
			printerInfo(p, "Self-update is disabled until signed releases are verified. Upgrade via a trusted path:")
			printerInfo(p, "  • "+styleCode.Render("curl -fsSL https://get.abysslink.dev/install.sh | sh")+" (verifies the release signature)")
			printerInfo(p, "  • your package manager (brew / apt / dnf), or")
			printerInfo(p, "  • "+styleCode.Render("go install github.com/abysslink/abysslink/cmd/abysslink@latest"))
			return nil
		},
	}
	cmd.Flags().Bool("check", false, "Only check for a newer version, do not upgrade")
	return cmd
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
