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

package codeserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBindAddrTailnetOnly(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		// Acceptable: specific tailnet IPs (v4 and v6) and MagicDNS names.
		{"100.64.1.2:8080", true},
		{"100.120.45.67:8080", true},
		{"[fd7a:115c:a1e0::1]:8080", true},
		{"mybox.tail1234.ts.net:8080", true},

		// Rejected: empty / wildcard hosts (NET-09 matrix).
		{"", false},
		{":8080", false},        // empty host — IPv4 all-interfaces
		{"0.0.0.0:8080", false}, // IPv4 wildcard with port
		{"0.0.0.0", false},      // IPv4 wildcard without port
		{"[::]:8080", false},    // IPv6 wildcard with port
		{"::", false},           // IPv6 wildcard without port
		{"[::]", false},         // bracketed IPv6 wildcard without port

		// Rejected: loopback hosts.
		{"127.0.0.1:8080", false},
		{"127.0.0.1", false},
		{"[::1]:8080", false},
		{"::1", false},
		{"localhost:8080", false},
		{"localhost", false},
		{"LOCALHOST:8080", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, isBindAddrTailnetOnly(tc.addr), "addr=%q", tc.addr)
	}
}
