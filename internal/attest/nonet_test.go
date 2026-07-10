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

package attest

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttestNoNetworkImports enforces the ATT-01 LOCAL-ONLY invariant by
// construction: every import of every non-test .go file in this package must
// be in the explicit ALLOWLIST below. Adding `net`, `net/http`, or any
// third-party SaaS client fails this test. It is an allowlist, not a
// denylist, so a future networked import cannot slip through unnamed.
// internal/shell is itself network-free, so direct-import checking suffices
// and keeps this test dependency-free.
func TestAttestNoNetworkImports(t *testing.T) {
	allow := map[string]bool{
		"context":       true,
		"errors":        true,
		"fmt":           true,
		"os":            true,
		"path/filepath": true,
		"regexp":        true,
		"strings":       true,
		"strconv":       true,
		"encoding/json": true,
		"log/slog":      true,
		"github.com/abysslink/abysslink/internal/shell": true,
	}

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	checked := 0
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		f, pErr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, pErr, "parse %s", name)
		for _, imp := range f.Imports {
			path, uErr := strconv.Unquote(imp.Path.Value)
			require.NoError(t, uErr)
			assert.True(t, allow[path],
				"%s imports %q which is NOT in the attest no-network allowlist (ATT-01: local-only, no SaaS verifier)", name, path)
		}
	}
	require.Greater(t, checked, 0, "the invariant must have scanned at least one file")
}
