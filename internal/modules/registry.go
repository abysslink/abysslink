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

package modules

import (
	"fmt"
	"sync"
)

var (
	mu       sync.RWMutex
	registry []Module
)

// Register adds a module to the global registry.
// Typically called from a module's init() function.
func Register(m Module) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, m)
}

// All returns a copy of all registered modules.
func All() []Module {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Module, len(registry))
	copy(out, registry)
	return out
}

// Get returns the module with the given name, or nil.
func Get(name string) Module {
	mu.RLock()
	defer mu.RUnlock()
	for _, m := range registry {
		if m.Name() == name {
			return m
		}
	}
	return nil
}

// TopoSort returns modules in dependency order (leaves first) using Kahn's algorithm.
// Returns an error if a cycle is detected.
func TopoSort(modules []Module) ([]Module, error) {
	if len(modules) == 0 {
		return []Module{}, nil
	}

	// Build an index from name → Module.
	index := make(map[string]Module, len(modules))
	for _, m := range modules {
		index[m.Name()] = m
	}

	// inDegree counts how many dependencies each module has (within the set).
	inDegree := make(map[string]int, len(modules))
	// adjacency: dep → list of modules that depend on dep.
	adjacency := make(map[string][]string, len(modules))

	for _, m := range modules {
		if _, exists := inDegree[m.Name()]; !exists {
			inDegree[m.Name()] = 0
		}
		for _, dep := range m.Deps() {
			// Only count deps that are present in the module set.
			if _, ok := index[dep]; !ok {
				continue
			}
			inDegree[m.Name()]++
			adjacency[dep] = append(adjacency[dep], m.Name())
		}
	}

	// Seed the queue with modules that have no dependencies (within the set).
	queue := make([]string, 0, len(modules))
	for _, m := range modules {
		if inDegree[m.Name()] == 0 {
			queue = append(queue, m.Name())
		}
	}

	sorted := make([]Module, 0, len(modules))
	for len(queue) > 0 {
		// Pop front.
		name := queue[0]
		queue = queue[1:]
		sorted = append(sorted, index[name])

		// Reduce in-degree for dependents.
		for _, dependent := range adjacency[name] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	if len(sorted) != len(modules) {
		return nil, fmt.Errorf("modules: dependency cycle detected")
	}

	return sorted, nil
}

// TopoSortReverse returns modules in reverse dependency order (for teardown).
func TopoSortReverse(modules []Module) ([]Module, error) {
	sorted, err := TopoSort(modules)
	if err != nil {
		return nil, err
	}
	// Reverse in place on a copy.
	out := make([]Module, len(sorted))
	for i, m := range sorted {
		out[len(sorted)-1-i] = m
	}
	return out, nil
}
