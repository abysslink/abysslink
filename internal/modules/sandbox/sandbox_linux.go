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
// (the FIRST non-blank line above — CRITICAL: any future go-landlock import
// must stay in a linux-tagged file or the macOS build breaks).
//
// License note: go-landlock (currently unused — see applyLandlockProfile)
// pulls one transitive dep, kernel.org/pub/linux/libs/security/libcap/psx,
// which is LGPLv2+. This is acceptable per the project depguard (only AGPL is
// banned); LGPLv2+ explicitly permits use by Apache-2.0-licensed software.
// See NOTICE.

import (
	"context"
	"log/slog"

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

// applyLandlockProfile applies the Landlock profile for the current process.
//
// CRITICAL: this function must NEVER call landlock.V1.RestrictPaths() with an
// empty rule set. There is no such thing as an "advisory empty profile": a
// Landlock ruleset with zero rules is an enforced DENY-ALL filesystem
// restriction applied irreversibly to the live abysslink process. On any
// kernel >= 5.13 that would break every subsequent filesystem operation in the
// same `up --apply` run (later modules' audit writes, backups, the audit log
// itself). See the isLandlockSupported doc comment above for the same trap in
// probe form.
//
// No path rules are currently configurable, so this is a documented no-op that
// only reports (truthfully, WR-03) whether the kernel could enforce a future
// non-empty profile. When operator-configured path rules land, build the
// ruleset here and return early — with a log — if the rule set is empty.
func applyLandlockProfile(_ context.Context) error {
	if !isLandlockSupported() {
		slog.Warn("sandbox: Landlock NOT enforced (kernel < 5.13 required); no process isolation applied")
		return nil
	}
	// Zero rules configured: skip entirely. Applying an empty ruleset would be
	// deny-all for the abysslink process itself, not isolation for services.
	slog.Info("sandbox: no Landlock path rules configured — skipping ruleset application (an empty ruleset would deny all filesystem access to abysslink itself)")
	return nil
}
