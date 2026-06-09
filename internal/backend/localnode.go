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

package backend

import (
	"os"
	"strings"
)

// localNodeCandidates returns the lowercase candidate names that identify THIS
// machine on the control plane: the configured tailnet hostname (the name the
// node enrolled under, when set) plus the OS hostname. Each candidate is also
// added in its short form (first DNS label) so "my-laptop.example.com" matches
// a control-plane entry named "my-laptop" and vice versa.
//
// NET-07: the Headscale /api/v1/node and NetBird /api/peers endpoints return
// the ACCOUNT-WIDE list — picking the first entry returns an arbitrary other
// machine on any network with more than one device. Adapters MUST match the
// local node against these candidates before returning identity data.
func localNodeCandidates(cfgHostname string) []string {
	var out []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			return
		}
		out = append(out, n)
		if i := strings.IndexByte(n, '.'); i > 0 {
			out = append(out, n[:i])
		}
	}
	add(cfgHostname)
	if h, err := os.Hostname(); err == nil {
		add(h)
	}
	return out
}

// matchesLocalNode reports whether any of the control-plane names (node name,
// given name, peer hostname, ...) identifies the local machine described by
// candidates. Comparison is case-insensitive and tolerates FQDN vs short-name
// mismatches in either direction.
func matchesLocalNode(candidates []string, names ...string) bool {
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		short := n
		if i := strings.IndexByte(n, '.'); i > 0 {
			short = n[:i]
		}
		for _, c := range candidates {
			if n == c || short == c {
				return true
			}
		}
	}
	return false
}
