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

// TEMPORARY — diagnoses the "Username for 'https://github.com':" prompt that
// appeared after `abysslink up --apply` at step 12/20 (ntfy module).
// Remove this file once the fix is confirmed working.

package ntfy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCloneNtfyTap_CallsGitDirectly verifies that cloneNtfyTap bypasses
// `brew tap` and calls git directly with -c credential.helper=.
//
// WHY this matters: Homebrew sanitizes its subprocess environment before
// forking git, resetting PATH and stripping GIT_* env vars. Every env-based
// suppression approach (GIT_TERMINAL_PROMPT=0, GIT_CONFIG_COUNT injection,
// PATH wrapper pointing to a git shim) is stripped before it reaches git.
// Calling git ourselves with -c credential.helper= is the only approach that
// cannot be stripped: git processes the -c flag before reading any config.
func TestCloneNtfyTap_CallsGitDirectly(t *testing.T) {
	fakeBrewRoot := t.TempDir() // tap dir absent here → clone path runs
	runner := shell.NewMockRunner(
		// brew --repository
		shell.Call{Result: shell.Result{Stdout: fakeBrewRoot + "\n", ExitCode: 0}},
		// git clone
		shell.Call{Result: shell.Result{Stdout: "", ExitCode: 0}},
	)
	m := New(modules.Deps{Runner: runner, Cfg: config.Defaults()})

	require.NoError(t, m.cloneNtfyTap(context.Background()))

	calls := runner.RecordedCalls()
	require.Len(t, calls, 2, "expected exactly: brew --repository, git clone")

	// Call 0: brew --repository — must NOT be brew tap.
	assert.Equal(t, "brew", calls[0].Name)
	assert.Equal(t, []string{"--repository"}, calls[0].Args)

	// Call 1: git — must NOT be brew tap (which routes through brew's Ruby
	// runtime where GIT_* env vars are stripped before git is forked).
	assert.Equal(t, "git", calls[1].Name,
		"must call git directly; brew tap routes through brew's Ruby runtime which sanitizes GIT_* env vars")

	args := calls[1].Args

	// -c credential.helper= is the key fix: clears all credential helpers
	// (including osxkeychain and gh auth git-credential) before git reads
	// any external config. Works on all git versions; not strippable by brew.
	foundCredHelper := false
	for i, a := range args {
		if a == "-c" && i+1 < len(args) && args[i+1] == "credential.helper=" {
			foundCredHelper = true
			break
		}
	}
	assert.True(t, foundCredHelper,
		"-c credential.helper= must be present; without it the user's configured credential helper prompts for GitHub credentials even when GIT_TERMINAL_PROMPT=0 is set")

	// -c http.prompt=false: belt-and-suspenders.
	foundHTTPPrompt := false
	for i, a := range args {
		if a == "-c" && i+1 < len(args) && args[i+1] == "http.prompt=false" {
			foundHTTPPrompt = true
			break
		}
	}
	assert.True(t, foundHTTPPrompt, "-c http.prompt=false must be present as belt-and-suspenders")

	// URL must be the ntfy Homebrew tap.
	foundURL := false
	for _, a := range args {
		if strings.Contains(a, "ntfy") && strings.HasSuffix(a, ".git") {
			foundURL = true
		}
	}
	assert.True(t, foundURL, "git clone URL must be the ntfy Homebrew tap")

	// Destination must be the standard Homebrew tap directory.
	dest := args[len(args)-1]
	wantSuffix := filepath.Join("Library", "Taps", "ntfy", "homebrew-ntfy")
	assert.True(t, strings.HasSuffix(dest, wantSuffix),
		"git clone destination %q must end with %q", dest, wantSuffix)

	// GIT_TERMINAL_PROMPT=0 in the RunWithEnv call (belt-and-suspenders for
	// our own git invocation; no effect on brew-internal git calls).
	assert.Equal(t, "0", calls[1].Env["GIT_TERMINAL_PROMPT"])
}

// TestCloneNtfyTap_SkipsIfAlreadyPresent verifies idempotency: when the tap
// directory already exists the function returns nil without calling git.
func TestCloneNtfyTap_SkipsIfAlreadyPresent(t *testing.T) {
	fakeBrewRoot := t.TempDir()
	tapDir := filepath.Join(fakeBrewRoot, "Library", "Taps", "ntfy", "homebrew-ntfy")
	require.NoError(t, os.MkdirAll(tapDir, 0o755))

	runner := shell.NewMockRunner(
		// brew --repository only — no git call expected.
		shell.Call{Result: shell.Result{Stdout: fakeBrewRoot + "\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Runner: runner, Cfg: config.Defaults()})

	require.NoError(t, m.cloneNtfyTap(context.Background()))
	assert.True(t, runner.Done(), "no git clone expected when tap dir already exists")
}
