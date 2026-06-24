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

// Package ui is the single-source-of-color leaf presentation package for
// Abysslink. It defines the Abyss brand palette (AdaptiveColor for brand
// tones, flat lipgloss.Color for semantic tones), reusable lipgloss styles,
// and the AbyssTheme() *huh.Theme used by interactive forms.
//
// This package is a sibling of internal/cli and internal/tui: it imports
// neither, and they import it. No import cycle can exist.
//
// Printer/IO-boundary exemption (D-07, Phase 34): the project hard rule is
// "only internal/cli writes stdout/stderr, via the Printer abstraction."
// internal/ui is a bounded exemption to that rule in the same structural
// shape as the v4.0.0 bbolt-outbox audit-mutation exemption
// (internal/push/doc.go, D-06, Phase 29):
//
//   - internal/ui NEVER writes stdout or stderr itself.
//   - internal/ui NEVER imports internal/cli (the cycle guard is the negative
//     proof; this comment is the affirmative deliverable).
//   - It emits styles and strings (theme/banner) consumed BY internal/cli and
//     the TUI layer, which then route them through Printer or huh.
//   - Deterministic/test-asserted output (--json / non-TTY / --yes paths)
//     continues to flow through Printer unchanged.
//   - Transient huh .Run() forms render beside Printer output; interactive()
//     (internal/cli/term.go:75) selects exactly one path per run.
//   - Headless / --yes / --json / non-TTY callers bypass huh entirely and
//     fail-soft to Printer (D-07 "two channels, one gate").
//
// Documented here so the architecture is visible at the package boundary.
package ui
