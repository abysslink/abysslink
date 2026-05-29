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

package tui_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/abysslink/abysslink/internal/tui"
)

// SecretBox output must contain the once-only warning line.
func TestSecretBox_OnceOnlyWarning(t *testing.T) {
	out := tui.SecretBox("Tailnet Lock Secrets", []string{"secret-a", "secret-b"})
	assert.Contains(t, out, "will NOT be shown again",
		"SecretBox must always include the once-only warning")
}

// SecretBox output must contain every secret passed in.
func TestSecretBox_ContainsSecrets(t *testing.T) {
	secrets := []string{"fake-secret-one", "fake-secret-two"}
	out := tui.SecretBox("Test Secrets", secrets)
	for _, s := range secrets {
		assert.Contains(t, out, s, "SecretBox must include every secret in the output")
	}
}

// SecretBox output must contain the title.
func TestSecretBox_ContainsTitle(t *testing.T) {
	out := tui.SecretBox("My Special Title", []string{"s1"})
	assert.Contains(t, out, "My Special Title")
}

// With NO_COLOR set, SecretBox must still render the box structure and the
// once-only warning (just without ANSI colour codes).
func TestSecretBox_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	out := tui.SecretBox("Tailnet Lock Secrets", []string{"secret-x"})
	assert.Contains(t, out, "will NOT be shown again")
	assert.Contains(t, out, "secret-x")
}
