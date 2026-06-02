//go:build !linux

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

// This file is the non-Linux stub, gated behind //go:build !linux (the FIRST
// non-blank line above). It MUST NOT import the go-landlock SDK — Landlock is a
// Linux-only kernel LSM, so the macOS/Windows build references no Landlock
// symbols and never panics. The function signatures here mirror
// sandbox_linux.go so module.go compiles on every platform.

import (
	"context"
)

// isLandlockSupported always reports false on non-Linux platforms.
func isLandlockSupported() bool { return false }

// applyLandlockProfile returns ErrNotSupported on non-Linux platforms — it
// never panics and never touches any Linux-specific syscall.
func applyLandlockProfile(_ context.Context) error { return ErrNotSupported }
