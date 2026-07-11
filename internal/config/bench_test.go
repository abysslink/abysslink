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

package config_test

import (
	"testing"

	"github.com/abysslink/abysslink/internal/config"
)

// P-C2 performance-budget benchmark for config parsing (MEASUREMENT ONLY — no
// regression gate). See docs/testing/perf-budget.md for the baseline + soft
// budget.

// benchConfigPath is the repo's representative example config — the same file
// TestLoad_MatchesExample loads (config_test.go). Relative to the config package
// dir, which is the CWD during `go test ./internal/config/...`.
const benchConfigPath = "../../abysslink.yaml.example"

// BenchmarkConfigLoad measures a full config.Load of a representative
// abysslink.yaml: open the file, YAML-decode with KnownFields(true), apply
// defaults, and run Validate (the fail-closed hot path every mutating command
// hits at startup).
func BenchmarkConfigLoad(b *testing.B) {
	// Sanity-check the fixture once so a path/validation failure surfaces before
	// the timed loop rather than as noise inside it.
	if _, err := config.Load(benchConfigPath); err != nil {
		b.Fatalf("load %s: %v", benchConfigPath, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := config.Load(benchConfigPath); err != nil {
			b.Fatalf("load: %v", err)
		}
	}
}
