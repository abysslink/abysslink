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

package quorum

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quorumSourceFiles returns the non-test Go sources of this package.
func quorumSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			out = append(out, name)
		}
	}
	require.NotEmpty(t, out)
	return out
}

// TestQuorum_NoOSExecImport: all exec goes through shell.Runner — the quorum
// decision path must never import os/exec (CLAUDE.md monopoly).
func TestQuorum_NoOSExecImport(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range quorumSourceFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, err)
		for _, imp := range f.Imports {
			assert.NotEqual(t, `"os/exec"`, imp.Path.Value,
				"%s must not import os/exec (V4 probes go through shell.Runner)", name)
		}
	}
}

// TestQuorum_NoNetImport: no network call participates in the decision path —
// no net, net/http, net/url, or any other net-rooted import.
func TestQuorum_NoNetImport(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range quorumSourceFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, err)
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			assert.False(t, p == "net" || strings.HasPrefix(p, "net/"),
				"%s imports %s — the quorum decision path must never touch the network", name, p)
		}
	}
}

// TestQuorum_NoClaude: the quorum is a generic gate-policy mechanism. Nothing
// Claude-specific may appear in its sources (APPR-06 quarantine: that logic
// belongs in the claudecode module).
func TestQuorum_NoClaude(t *testing.T) {
	for _, name := range quorumSourceFiles(t) {
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		assert.NotContains(t, strings.ToLower(string(src)), "claude",
			"%s mentions claude — the quorum must stay generic", name)
	}
}
