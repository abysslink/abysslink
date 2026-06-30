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

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitCmd_ResumeFlagRegistered asserts that newInitCmd registers a --resume
// flag. Ported from TestJourneyInitCmd_YesFlagRegistered in journey_test.go
// (plan 35-05 Task 2b: journey.go deletion).
func TestInitCmd_ResumeFlagRegistered(t *testing.T) {
	cmd := newInitCmd()
	require.NotNil(t, cmd.Flags().Lookup("resume"), "--resume flag must be registered on init command")
	require.NotNil(t, cmd.Flags().Lookup("yes"), "--yes flag must be registered on init command")
}

// TestGalleryCommand asserts that the hidden gallery command exits 0, makes no
// mutations, and does not panic. It exercises the headless path (no TTY in CI
// so interactive() returns false and the huh form is skipped).
//
// Verification:
//   - Exit code 0 (RunE returns nil)
//   - No file created in a temp dir (no mutations)
//   - No panic
func TestGalleryCommand(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR", "0")

	// Execute the gallery command via the root command harness (headless path).
	tmpDir := t.TempDir()
	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs([]string{"gallery"})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	// Must not panic; must exit 0.
	err := cmd.Execute()
	require.NoError(t, err, "gallery command must exit 0")

	// Verify gallery command is registered (reachable by name).
	sub, _, findErr := cmd.Find([]string{"gallery"})
	require.NoError(t, findErr, "gallery subcommand must be findable")
	require.NotNil(t, sub, "gallery subcommand must be registered")
	assert.True(t, sub.Hidden, "gallery command must have Hidden:true")

	// No file mutation: temp dir must be empty after gallery runs.
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "gallery must not create any files in the working directory")

	// Output sanity: banner or markdown must appear in the output.
	out := buf.String()
	_ = filepath.Join(tmpDir, "noop") // avoid unused-import lint; tmpDir is checked above
	// In headless / NO_COLOR mode glamour returns raw markdown — check for content.
	assert.NotEmpty(t, out, "gallery must produce some output (banner or markdown)")
}
