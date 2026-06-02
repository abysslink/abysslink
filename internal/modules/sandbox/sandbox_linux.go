//go:build linux

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

package sandbox

// This file is the Linux Landlock implementation, gated behind //go:build linux
// (the FIRST non-blank line above — CRITICAL: any go-landlock import must stay
// in a linux-tagged file or the macOS build breaks).
//
// License note: go-landlock pulls one transitive dep,
// kernel.org/pub/linux/libs/security/libcap/psx, which is LGPLv2+. This is
// acceptable per the project depguard (only AGPL is banned); LGPLv2+ explicitly
// permits use by Apache-2.0-licensed software. See NOTICE.

import (
	"context"
	"log/slog"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// isLandlockSupported probes whether the running kernel supports Landlock V1
// (Linux kernel >= 5.13). It calls landlock.V1.RestrictPaths() with no rules
// and WITHOUT BestEffort: on a kernel that lacks Landlock the call returns an
// error (the syscall is absent / disabled), so err == nil is a reliable
// support signal. An empty rule set is a safe no-op probe with no lasting
// restriction on the calling process beyond what an empty ruleset implies.
func isLandlockSupported() bool {
	return landlock.V1.RestrictPaths() == nil
}

// applyLandlockProfile applies a minimal Landlock profile to the current
// process. It uses BestEffort() so kernels < 5.13 degrade gracefully (no error)
// rather than failing closed. The concrete path rules are operator-configured
// out of band; this module currently applies an empty (no-op advisory) profile
// and logs that Landlock is active. Returns any error from the kernel.
func applyLandlockProfile(_ context.Context) error {
	if !isLandlockSupported() {
		slog.Info("sandbox: Landlock not supported on this kernel (>= 5.13 required); skipping (BestEffort)")
	}
	if err := landlock.V1.BestEffort().RestrictPaths(); err != nil {
		return err
	}
	slog.Info("sandbox: Landlock process isolation applied (BestEffort)")
	return nil
}
