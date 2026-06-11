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
		// DOC-02 / D-06: lsblk unavailable → disk-encryption state is UNKNOWN → FATAL.
		// Stable marker "disk-encryption state is UNKNOWN" used by Plan 04's up gate.
		// Message must NOT offer a bypass (D-05).
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "luks",
			Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN: lsblk is unavailable or failed to run — " +
				"verify LUKS encryption manually with: cryptsetup status <device>",
		}}, nil
	}
	if res.ExitCode != 0 {
		slog.Warn("hardening detect: lsblk exited non-zero", "stderr", res.Stderr)
		// DOC-02: non-zero exit → state unknown.
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "luks",
			Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN: lsblk exited with a non-zero status — " +
				"verify LUKS encryption manually with: cryptsetup status <device>",
		}}, nil
	}

	var output lsblkOutput
	if err := json.Unmarshal([]byte(res.Stdout), &output); err != nil {
		slog.Warn("hardening detect: could not parse lsblk JSON", "error", err)
		// DOC-02: unparseable JSON → state unknown.
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "luks",
			Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN: lsblk returned unparseable JSON — " +
				"verify LUKS encryption manually with: cryptsetup status <device>",
		}}, nil
	}

	encrypted := isHomeEncrypted(home, output.Blockdevices)
	slog.Debug("luks check", "home", home, "encrypted", encrypted)

	if !encrypted {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "luks",
			Severity: modules.SeverityFatal,
			Message:  "Home directory is not on an encrypted (LUKS) filesystem — enable full-disk encryption before exposing remote access",
		}}, nil
	}

	// DOC-01 backfill: emit SeverityOK on the genuinely-encrypted clean path.
	// Emitted only in checkLUKS (called once per detectPlatform invocation) to
	// prevent double-emission — Detect and Verify both call detectPlatform, so
	// the finding appears at most once per doctor pass per detectPlatform call.
	return []modules.Finding{{
		Module:   m.Name(),
		Check:    "luks",
		Severity: modules.SeverityOK,
		Message:  "Home directory is on an encrypted (LUKS) filesystem",
	}}, nil
}

// isHomeEncrypted returns true if the filesystem that actually hosts home —
// the device with the LONGEST mountpoint that is an ancestor of home — has a
// "crypt" type ancestor (i.e., LUKS) in its device chain.
//
// The longest-match rule matters (W5): with a LUKS root (/) and a separate
// PLAINTEXT /home partition, "/" also covers $HOME, so testing "any covering
// mount is crypt" would pass while the user's actual data sits unencrypted.
// Only the deepest covering mountpoint reflects where home really lives.
func isHomeEncrypted(home string, devices []lsblkDevice) bool {
	best := mountMatch{}
	for _, dev := range devices {
		findHomeMount(home, dev, false, &best)
	}
	return best.found && best.crypt
}

// mountMatch tracks the deepest mountpoint covering home seen so far and
// whether that device's chain contains a crypt ancestor.
type mountMatch struct {
	found      bool
	mountpoint string
	crypt      bool
}

// findHomeMount recurses through the device tree. parentIsCrypt tracks whether
// any ancestor in the chain has type == "crypt". Every device whose mountpoint
// covers home is a candidate; the one with the longest (deepest) mountpoint
// wins because that is the filesystem home actually resides on.
func findHomeMount(home string, dev lsblkDevice, parentIsCrypt bool, best *mountMatch) {
	isCrypt := parentIsCrypt || strings.EqualFold(dev.Type, "crypt")

	if dev.MountPoint != "" && isUnderPath(home, dev.MountPoint) {
		if !best.found || len(filepath.Clean(dev.MountPoint)) > len(filepath.Clean(best.mountpoint)) {
			best.found = true
			best.mountpoint = dev.MountPoint
			best.crypt = isCrypt
		}
	}

	for _, child := range dev.Children {
		findHomeMount(home, child, isCrypt, best)
	}
}

// isUnderPath returns true if target is at or under base.
func isUnderPath(target, base string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}
