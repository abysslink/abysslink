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

package tailscale

import (
	"testing"
)

// FuzzHuJSONParse exercises NewACLEditor (the HuJSON Standardize + unmarshal
// path) against arbitrary bytes. The parser must fail closed (return an error,
// never panic) on malformed input — that is the property under test
// (AUD-08, T-17-16).
func FuzzHuJSONParse(f *testing.F) {
	// Seed corpus — mirrors the files in testdata/fuzz/FuzzHuJSONParse/.
	f.Add([]byte(""))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"grants":[{"src":["tag:mobile"],"dst":["tag:laptop"],"ip":["tcp:22"]}]}`))
	f.Add([]byte(`{invalid hujson`))

	f.Fuzz(func(_ *testing.T, b []byte) {
		if len(b) > 4096 {
			return // guard against CI OOM — MUST be the first statement
		}
		if _, err := NewACLEditor(b); err != nil {
			return // malformed HuJSON is expected to error, not panic
		}
	})
}
