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

package budget

import "context"

// tokenCounter is the interface satisfied by tokenParser.
// When token-tier observation is enabled (D-04 opt-in), the Watcher will call
// TotalTokens on each check cycle and compare against BudgetConfig.TokenTiers
// thresholds. In v1 this interface is wired to the no-op stub below.
type tokenCounter interface {
	TotalTokens(ctx context.Context) (int, error)
}

// tokenParser is the opt-in Claude Code JSONL session-log parser (D-04).
// Disabled by default; enabled when BudgetConfig.TokenTiers.JSONLPath is set.
// The parser stub returns 0 tokens until the opt-in feature is wired.
//
// Claude Code writes session JSONL to ~/.claude/projects/<hash>/...
// Each line is a JSON object containing usage information. The relevant fields
// are implementation-specific and may vary across Claude Code versions.
//
// TODO(phase-31-opt-in): read actual JSONL schema when enabling the
// token-tier feature (D-04). JSONLPath must be set in BudgetConfig.TokenTiers
// to activate; the parser is a no-op stub in v1.
type tokenParser struct {
	// path is the filesystem path to the Claude Code JSONL session log.
	// Unused in the v1 stub; wired when the token-tier opt-in is enabled (D-04).
	path string //nolint:unused // D-04: stub field; wired at phase-31-opt-in
}

// compile-time: tokenParser must satisfy tokenCounter.
var _ tokenCounter = (*tokenParser)(nil)

// TotalTokens returns the total token count from the JSONL session log.
// Returns (0, nil) in the stub implementation (D-04: token tiers off by default in v1).
func (p *tokenParser) TotalTokens(_ context.Context) (int, error) {
	_ = p.path // D-04 stub: path is read when the opt-in feature is enabled
	return 0, nil
}
