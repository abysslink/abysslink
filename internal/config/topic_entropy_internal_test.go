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

// Package config — internal tests for the unexported B9 topic-entropy floor.
package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNtfyTopicEntropyFloor verifies B9 (T-32-16): a topic carrying a ≥128-bit
// (≥32 hex char) random suffix passes the floor; a legacy below-floor suffix
// (e.g. 8 hex chars / 32 bits) fails it.
func TestNtfyTopicEntropyFloor(t *testing.T) {
	cases := []struct {
		name  string
		topic string
		want  bool
	}{
		{"128-bit suffix", "abysslink-vaultofmac-0123456789abcdef0123456789abcdef", true},
		{"legacy 32-bit suffix", "abysslink-vaultofmac-deadbeef", false},
		{"empty", "", false},
		{"no random component", "abysslink-vaultofmac-", false},
		{"non-prefixed custom topic", "my-custom-topic", false},
		{"just under floor (31 hex)", "abysslink-rig-0123456789abcdef0123456789abcde", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ntfyTopicHasFloorEntropy(tc.topic))
		})
	}
}
