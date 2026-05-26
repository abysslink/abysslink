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

package modules_test

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubModule is a minimal Module implementation used only for registry/topo tests.
type stubModule struct {
	name string
	deps []string
}

func (s *stubModule) Name() string                                        { return s.name }
func (s *stubModule) Deps() []string                                      { return s.deps }
func (s *stubModule) Detect(_ context.Context) ([]modules.Finding, error) { return nil, nil }
func (s *stubModule) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	return nil, nil
}
func (s *stubModule) Apply(_ context.Context) error                       { return nil }
func (s *stubModule) Verify(_ context.Context) ([]modules.Finding, error) { return nil, nil }
func (s *stubModule) Repair(_ context.Context) error                      { return nil }

func newStub(name string, deps ...string) modules.Module {
	return &stubModule{name: name, deps: deps}
}

// nameList extracts names from an ordered module slice for easy assertion.
func nameList(ms []modules.Module) []string {
	names := make([]string, len(ms))
	for i, m := range ms {
		names[i] = m.Name()
	}
	return names
}

func TestTopoSort_Linear(t *testing.T) {
	// A has no deps, B depends on A, C depends on B → expected order [A, B, C].
	mods := []modules.Module{
		newStub("C", "B"),
		newStub("B", "A"),
		newStub("A"),
	}
	sorted, err := modules.TopoSort(mods)
	require.NoError(t, err)
	names := nameList(sorted)
	assert.Equal(t, []string{"A", "B", "C"}, names)
}

func TestTopoSort_Diamond(t *testing.T) {
	// D depends on B and C; B and C both depend on A.
	// Valid orders: [A, B, C, D] or [A, C, B, D].
	mods := []modules.Module{
		newStub("D", "B", "C"),
		newStub("B", "A"),
		newStub("C", "A"),
		newStub("A"),
	}
	sorted, err := modules.TopoSort(mods)
	require.NoError(t, err)
	require.Len(t, sorted, 4)

	names := nameList(sorted)
	// A must appear before B, C, and D.
	idxA := indexOf(names, "A")
	idxB := indexOf(names, "B")
	idxC := indexOf(names, "C")
	idxD := indexOf(names, "D")
	assert.Less(t, idxA, idxB, "A must precede B")
	assert.Less(t, idxA, idxC, "A must precede C")
	assert.Less(t, idxB, idxD, "B must precede D")
	assert.Less(t, idxC, idxD, "C must precede D")
}

func indexOf(names []string, target string) int {
	for i, n := range names {
		if n == target {
			return i
		}
	}
	return -1
}

func TestTopoSort_Cycle(t *testing.T) {
	// A → B → A is a cycle.
	mods := []modules.Module{
		newStub("A", "B"),
		newStub("B", "A"),
	}
	_, err := modules.TopoSort(mods)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
}

func TestTopoSort_Empty(t *testing.T) {
	sorted, err := modules.TopoSort([]modules.Module{})
	require.NoError(t, err)
	assert.Empty(t, sorted)
}

func TestTopoSort_NoDeps(t *testing.T) {
	// Three independent modules — all should appear in the result.
	mods := []modules.Module{
		newStub("X"),
		newStub("Y"),
		newStub("Z"),
	}
	sorted, err := modules.TopoSort(mods)
	require.NoError(t, err)
	require.Len(t, sorted, 3)

	names := nameList(sorted)
	assert.ElementsMatch(t, []string{"X", "Y", "Z"}, names)
}

func TestRegister_Get(t *testing.T) {
	// Use a unique name to avoid collisions with other tests sharing the global registry.
	m := newStub("test-register-get-unique")
	modules.Register(m)
	got := modules.Get("test-register-get-unique")
	require.NotNil(t, got)
	assert.Equal(t, "test-register-get-unique", got.Name())
}

func TestAll(t *testing.T) {
	// Register a module with a unique name and confirm All() contains it.
	m := newStub("test-all-unique")
	modules.Register(m)
	all := modules.All()
	names := nameList(all)
	assert.Contains(t, names, "test-all-unique")
}
