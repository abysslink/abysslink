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

// normalizeNodeName lowercases a control-plane or local hostname and strips
// surrounding whitespace and any trailing FQDN dot.
func normalizeNodeName(n string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
}

// shortNodeName returns the first DNS label of an already-normalized name, so
// "my-laptop.example.com" → "my-laptop".
func shortNodeName(n string) string {
	if i := strings.IndexByte(n, '.'); i > 0 {
		return n[:i]
	}
	return n
}

// localNodeCandidates returns the lowercase candidate names that identify THIS
// machine on the control plane: the configured tailnet hostname (the name the
// node enrolled under, when set) plus the OS hostname. Each candidate is also
// added in its short form (first DNS label) so "my-laptop.example.com" matches
// a control-plane entry named "my-laptop" and vice versa.
//
// Used for error messages; the actual matching is done by findLocalNodes.
func localNodeCandidates(cfgHostname string) []string {
	var out []string
	add := func(n string) {
		n = normalizeNodeName(n)
		if n == "" {
			return
		}
		out = append(out, n)
		if s := shortNodeName(n); s != n {
			out = append(out, s)
		}
	}
	add(cfgHostname)
	if h, err := os.Hostname(); err == nil {
		add(h)
	}
	return out
}

// findLocalNodes returns the indices of the control-plane entries that
// identify THIS machine, given the configured tailnet hostname and a namesAt
// accessor returning the control-plane names (node name, given name, peer
// hostname, dns label, ...) of entry i.
//
// NET-07: the Headscale /api/v1/node and NetBird /api/peers endpoints return
// the ACCOUNT-WIDE list — picking the first entry returns an arbitrary other
// machine on any network with more than one device. Adapters MUST match the
// local node against these candidates before returning identity data.
//
// Matching runs in priority tiers so an exactly-configured hostname is never
// reported ambiguous against another node that merely shares its short name
// ("laptop.a" configured must not collide with "laptop.b"):
//
//  1. exact match against the configured tailnet hostname
//  2. short-name (first DNS label) match against the configured hostname
//  3. exact match against the OS hostname
//  4. short-name match against the OS hostname
//
// The first tier with any matches wins. More than one match within that tier
// is a genuine ambiguity — callers must surface it as an error rather than
// silently returning an arbitrary machine's identity.
func findLocalNodes(cfgHostname string, n int, namesAt func(int) []string) []int {
	var candidates []string
	if c := normalizeNodeName(cfgHostname); c != "" {
		candidates = append(candidates, c)
	}
	if h, err := os.Hostname(); err == nil {
		if c := normalizeNodeName(h); c != "" {
			candidates = append(candidates, c)
		}
	}

	for _, cand := range candidates {
		for _, exact := range []bool{true, false} {
			var matches []int
			for i := 0; i < n; i++ {
				if nodeNamesMatch(cand, namesAt(i), exact) {
					matches = append(matches, i)
				}
			}
			if len(matches) > 0 {
				return matches
			}
		}
	}
	return nil
}

// nodeNamesMatch reports whether any of the control-plane names identifies the
// candidate. In exact mode the full normalized names must be equal; in fuzzy
// mode the first DNS labels are compared, tolerating FQDN vs short-name
// mismatches in either direction.
func nodeNamesMatch(cand string, names []string, exact bool) bool {
	for _, nm := range names {
		nm = normalizeNodeName(nm)
		if nm == "" {
			continue
		}
		if exact {
			if nm == cand {
				return true
			}
			continue
		}
		if shortNodeName(nm) == shortNodeName(cand) {
			return true
		}
	}
	return false
}
