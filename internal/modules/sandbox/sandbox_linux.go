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
	"golang.org/x/sys/unix"
)

// isLandlockSupported probes whether the running kernel supports Landlock V1
// (Linux kernel >= 5.13) WITHOUT enforcing any restriction on the caller.
//
// It queries the supported Landlock ABI version via
// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION): the kernel
// returns the ABI version (>= 1 when Landlock is available) and creates no
// ruleset, so the calling process is left completely unrestricted. On a kernel
// without Landlock the syscall fails (ENOSYS / EOPNOTSUPP).
//
// It must NOT probe by calling landlock.V1.RestrictPaths(): with no rules that
// applies a deny-all empty ruleset to the live process — irreversibly — which
// would break every later filesystem write in the same process (e.g. it would
// lock `abysslink doctor` out of the filesystem mid-run).
func isLandlockSupported() bool {
	const landlockCreateRulesetVersion = 1 // LANDLOCK_CREATE_RULESET_VERSION
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, landlockCreateRulesetVersion)
	return errno == 0 && int(abi) >= 1
}

// applyLandlockProfile applies a minimal Landlock profile to the current
// process. It uses BestEffort() so kernels < 5.13 degrade gracefully (no error)
// rather than failing closed. The concrete path rules are operator-configured
// out of band; this module currently applies an empty (advisory no-op) profile.
//
// Logging is truthful about enforcement (WR-03): it probes Landlock support
// first and only claims isolation when the kernel actually enforces it. On an
// unsupported kernel (< 5.13) BestEffort applies nothing, so it logs a WARN
// stating Landlock is NOT enforced rather than a misleading "applied" message.
// Returns any error from the kernel.
func applyLandlockProfile(_ context.Context) error {
	if !isLandlockSupported() {
		slog.Warn("sandbox: Landlock NOT enforced (kernel < 5.13 required); no process isolation applied")
		return nil
	}
	if err := landlock.V1.BestEffort().RestrictPaths(); err != nil {
		return err
	}
	slog.Info("sandbox: Landlock process isolation applied (BestEffort, empty advisory profile)")
	return nil
}
