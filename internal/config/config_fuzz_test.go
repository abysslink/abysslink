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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
)

// FuzzConfigLoad exercises config.Load against arbitrary YAML bytes. Load must
// fail closed (return an error, never panic) on malformed input — that is the
// property under test (AUD-08, T-17-16). It is an external test package so it
// drives only the exported Load API.
func FuzzConfigLoad(f *testing.F) {
	// Seed corpus — mirrors the files in testdata/fuzz/FuzzConfigLoad/.
	f.Add([]byte(""))
	f.Add([]byte("backend:\n  type: tailscale\n"))
	f.Add([]byte(strings.Repeat("# padding comment line\n", 150)))
	f.Add([]byte("{ invalid: yaml: :::"))

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return // guard against CI OOM — MUST be the first statement
		}
		tmp := filepath.Join(t.TempDir(), "abysslink.yaml")
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return // tmp write failure is environmental, not a parser crash
		}
		if _, err := config.Load(tmp); err != nil {
			return // malformed YAML is expected to error, not panic
		}
	})
}
