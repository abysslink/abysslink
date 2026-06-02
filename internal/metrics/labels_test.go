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

package metrics_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/abysslink/abysslink/internal/metrics"
)

func TestSanitizeLabelAllowed(t *testing.T) {
	for _, name := range []string{"severity", "check_id", "backend", "result", "rig"} {
		assert.Equal(t, name, metrics.SanitizeLabel(name), "allowlisted label must pass through unchanged")
	}
}

func TestSanitizeLabelRejected(t *testing.T) {
	for _, name := range []string{"hostname", "topic", "user", "node_id", "ip", "password", ""} {
		assert.Equal(t, "other", metrics.SanitizeLabel(name), "unlisted label %q must map to other", name)
	}
}

func TestOpaqueRigLabelDeterministic(t *testing.T) {
	a := metrics.OpaqueRigLabel("laptop-01")
	b := metrics.OpaqueRigLabel("laptop-01")
	assert.Equal(t, a, b)
}

func TestOpaqueRigLabelNonReversible(t *testing.T) {
	out := metrics.OpaqueRigLabel("laptop-01")
	assert.NotContains(t, out, "laptop")
	assert.NotContains(t, out, "01")
}

func TestOpaqueRigLabelLength(t *testing.T) {
	out := metrics.OpaqueRigLabel("any-rig-name")
	assert.Len(t, out, 16)
	// 16 hex characters only.
	assert.Equal(t, "", strings.Trim(out, "0123456789abcdef"))
}
