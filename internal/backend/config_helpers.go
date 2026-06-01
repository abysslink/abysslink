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

// Package backend implements the backend adapter layer for abysslink.
package backend

// setNestedKey sets a dotted-path key inside a map[string]any, creating
// intermediate maps as needed. This is the safe surgical-merge primitive:
// it never overwrites a user-owned sub-map's OTHER keys.
//
//   - keys: ordered path components, e.g. []string{"derp", "server", "verify_clients"}
//   - val: the value to set at the leaf
//
// Example: setNestedKey(m, []string{"derp","server","verify_clients"}, true)
// ensures m["derp"]["server"]["verify_clients"] == true while preserving any
// other keys under m["derp"]["server"].
//
// This is the single canonical implementation shared by MergeHeadscaleConfig
// and MergeNetBirdConfig. Do NOT duplicate this function in other files.
func setNestedKey(m map[string]any, keys []string, val any) {
	if len(keys) == 0 {
		return
	}
	if len(keys) == 1 {
		m[keys[0]] = val
		return
	}
	// Descend into or create the intermediate map.
	sub, ok := m[keys[0]].(map[string]any)
	if !ok {
		sub = make(map[string]any)
	}
	setNestedKey(sub, keys[1:], val)
	m[keys[0]] = sub
}
