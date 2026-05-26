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

//go:build linux

package hardening

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/modules"
)

// lsblkOutput is the JSON structure from `lsblk --json`.
type lsblkOutput struct {
	Blockdevices []lsblkDevice `json:"blockdevices"`
}

// lsblkDevice represents a single block device entry.
type lsblkDevice struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	MountPoint string        `json:"mountpoint"`
	Children   []lsblkDevice `json:"children"`
}

// detectPlatform runs Linux-specific hardening checks.
func detectPlatform(ctx context.Context, m *Module) ([]modules.Finding, error) {
	var findings []modules.Finding

	luksFindings, err := checkLUKS(ctx, m)
	if err != nil {
		return findings, fmt.Errorf("hardening detect: luks: %w", err)
	}
	findings = append(findings, luksFindings...)

	return findings, nil
}

// checkLUKS uses lsblk to detect whether the home directory is on an encrypted device.
func checkLUKS(ctx context.Context, m *Module) ([]modules.Finding, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	res, err := m.runner.Run(ctx, "lsblk", "--json", "--output", "NAME,TYPE,MOUNTPOINT")
	if err != nil {
		slog.Warn("hardening detect: lsblk failed", "error", err)
		return nil, nil
	}
	if res.ExitCode != 0 {
		slog.Warn("hardening detect: lsblk exited non-zero", "stderr", res.Stderr)
		return nil, nil
	}

	var output lsblkOutput
	if err := json.Unmarshal([]byte(res.Stdout), &output); err != nil {
		slog.Warn("hardening detect: could not parse lsblk JSON", "error", err)
		return nil, nil
	}

	encrypted := isHomeEncrypted(home, output.Blockdevices)
	slog.Debug("luks check", "home", home, "encrypted", encrypted)

	if !encrypted {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "luks",
			Severity: modules.SeverityWarning,
			Message:  "Home directory is not on an encrypted filesystem",
		}}, nil
	}

	return nil, nil
}

// isHomeEncrypted returns true if the block device tree that mounts home
// has a "crypt" type ancestor (i.e., LUKS).
func isHomeEncrypted(home string, devices []lsblkDevice) bool {
	for _, dev := range devices {
		if deviceContainsHome(home, dev, false) {
			return true
		}
	}
	return false
}

// deviceContainsHome recurses through the device tree. parentIsCrypt tracks
// whether any ancestor in the chain has type == "crypt".
func deviceContainsHome(home string, dev lsblkDevice, parentIsCrypt bool) bool {
	isCrypt := parentIsCrypt || strings.EqualFold(dev.Type, "crypt")

	if dev.MountPoint != "" && isUnderPath(home, dev.MountPoint) {
		return isCrypt
	}

	for _, child := range dev.Children {
		if deviceContainsHome(home, child, isCrypt) {
			return true
		}
	}

	return false
}

// isUnderPath returns true if target is at or under base.
func isUnderPath(target, base string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}
