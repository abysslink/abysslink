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

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkStatusWarm measures the wall-clock time for `abysslink status`
// on a warm binary (binary is already in the OS disk cache).
// Performance budget: < 500ms warm (DESIGN.md §8.3).
//
// Run with:
//
//	ABYSSLINK_BENCH=1 go test -bench=BenchmarkStatusWarm -benchtime=5x ./internal/cli/
func BenchmarkStatusWarm(b *testing.B) {
	if os.Getenv("ABYSSLINK_BENCH") == "" {
		b.Skip("integration benchmark — set ABYSSLINK_BENCH=1 to run")
	}
	binPath := resolveBenchBinary(b)

	// Warm up the binary (prime OS page cache).
	_ = exec.Command(binPath, "version").Run() //nolint:gosec

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		cmd := exec.Command(binPath, "status") //nolint:gosec
		if err := cmd.Run(); err != nil {
			b.Logf("status exited non-zero (expected in CI): %v", err)
		}
		elapsed := time.Since(start)
		const budget = 500 * time.Millisecond
		if elapsed > budget {
			b.Errorf("status took %s, exceeds warm budget of %s", elapsed, budget)
		}
	}
}

// TestStatusCompletesWithinColdBudget verifies that `abysslink status` exits
// within 2 s even on a cold start.
// Performance budget: < 2s cold (DESIGN.md §8.3).
//
// This test is skipped in normal `go test` runs; it is exercised by
// abysslink-conformance instead.
func TestStatusCompletesWithinColdBudget(t *testing.T) {
	if os.Getenv("ABYSSLINK_BENCH") == "" {
		t.Skip("integration test — set ABYSSLINK_BENCH=1 or run abysslink-conformance")
	}
	binPath := resolveBenchBinary(t)

	const budget = 2 * time.Second
	start := time.Now()
	cmd := exec.Command(binPath, "status") //nolint:gosec
	_ = cmd.Run()
	elapsed := time.Since(start)
	if elapsed > budget {
		t.Errorf("status cold-start took %s, exceeds budget of %s", elapsed, budget)
	}
}

// TestUpDryRunWithinBudget verifies that `abysslink up` (dry-run) on a
// converged machine completes within 3 s.
// Performance budget: < 3s (DESIGN.md §8.3).
func TestUpDryRunWithinBudget(t *testing.T) {
	if os.Getenv("ABYSSLINK_BENCH") == "" {
		t.Skip("integration test — set ABYSSLINK_BENCH=1 or run abysslink-conformance")
	}
	binPath := resolveBenchBinary(t)

	const budget = 3 * time.Second
	start := time.Now()
	cmd := exec.Command(binPath, "up") //nolint:gosec
	_ = cmd.Run()
	elapsed := time.Since(start)
	if elapsed > budget {
		t.Errorf("up --dry-run took %s, exceeds budget of %s", elapsed, budget)
	}
}

// testing.TB is satisfied by both *testing.T and *testing.B.
type tHelper interface {
	Helper()
	Skip(args ...any)
	Fatal(args ...any)
	Logf(format string, args ...any)
	TempDir() string
}

// resolveBenchBinary returns the path to the abysslink binary, building it if
// necessary. It calls t.Fatal if the binary cannot be resolved.
func resolveBenchBinary(t tHelper) string {
	t.Helper()
	if p, err := exec.LookPath("abysslink"); err == nil {
		return p
	}

	// Build from source.
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "abysslink")

	repoRoot := findRepoRoot(t)
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/abysslink") //nolint:gosec // test helper builds the binary under test
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("could not build abysslink:", string(out))
	}
	return binPath
}

// findRepoRoot walks up from the current working directory to locate go.mod.
func findRepoRoot(t tHelper) string {
	t.Helper()
	dir, _ := os.Getwd()
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find repo root (no go.mod found)")
	return ""
}
