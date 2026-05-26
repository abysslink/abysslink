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

// Command abysslink-conformance drives end-to-end conformance tests for abysslink.
// It builds the abysslink binary if not in PATH, then runs a suite of scenarios
// against it using a temporary config directory so the real user config is untouched.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	binPath, err := locateBinary(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: could not obtain abysslink binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Using binary: %s\n", binPath)

	tempDir, err := os.MkdirTemp("", "abysslink-conformance-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: could not create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	configPath := filepath.Join(tempDir, "config.yaml")

	type scenario struct {
		name string
		fn   func(ctx context.Context) error
	}

	scenarios := []scenario{
		{
			name: "version output contains abysslink",
			fn:   func(ctx context.Context) error { return testVersionOutput(ctx, binPath) },
		},
		{
			name: "init creates config",
			fn:   func(ctx context.Context) error { return testInitCreatesConfig(ctx, binPath, tempDir, configPath) },
		},
		{
			name: "up dry-run exits 0 and prints Dry-run mode",
			fn:   func(ctx context.Context) error { return testUpDryRun(ctx, binPath, configPath) },
		},
		{
			name: "doctor exits without panic",
			fn:   func(ctx context.Context) error { return testDoctorExitCodes(ctx, binPath, configPath) },
		},
		{
			name: "status --json emits valid JSON",
			fn:   func(ctx context.Context) error { return testStatusJSON(ctx, binPath, configPath) },
		},
		{
			name: "panic command completes without hang (15s timeout)",
			fn:   func(ctx context.Context) error { return testPanicNoHang(ctx, binPath, configPath) },
		},
		{
			name: "notify --stdin completes without hang",
			fn:   func(ctx context.Context) error { return testNotifyStdin(ctx, binPath, configPath) },
		},
		{
			name: "disable + enable round-trip exits 0",
			fn:   func(ctx context.Context) error { return testDisableEnableRoundTrip(ctx, binPath, configPath) },
		},
	}

	passed := 0
	failed := 0

	for _, s := range scenarios {
		scenCtx, scenCancel := context.WithTimeout(ctx, 30*time.Second)
		if err := s.fn(scenCtx); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL [%s]: %v\n", s.name, err)
			failed++
		} else {
			fmt.Printf("PASS [%s]\n", s.name)
			passed++
		}
		scenCancel()
	}

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// locateBinary finds the abysslink binary in PATH, or builds it from source.
func locateBinary(ctx context.Context) (string, error) {
	if p, err := exec.LookPath("abysslink"); err == nil {
		return p, nil
	}

	// Not in PATH — build it.
	repoRoot, err := getRepoRoot()
	if err != nil {
		return "", fmt.Errorf("locate repo root: %w", err)
	}

	binName := "abysslink"
	if runtime.GOOS == "windows" {
		binName = "abysslink.exe"
	}
	binPath := filepath.Join(os.TempDir(), "abysslink-conformance-bin-"+binName)

	cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/abysslink") //nolint:gosec // conformance harness intentionally runs go build
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go build ./cmd/abysslink: %w", err)
	}
	return binPath, nil
}

// getRepoRoot walks up from this file's location until it finds go.mod.
func getRepoRoot() (string, error) {
	// Start from this executable's location.
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)

	// Try up to 10 levels.
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Fallback: check if we can find it relative to the source file.
	// When run via "go run ./cmd/abysslink-conformance" the CWD is repo root.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for _, candidate := range []string{cwd, filepath.Join(cwd, "..", "..", "..")} {
		candidate = filepath.Clean(candidate)
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not find repo root (no go.mod found walking up from %s)", exe)
}

// runAbysslink executes the abysslink binary with the given arguments.
// It returns combined stdout+stderr and the exit error (nil on exit 0).
func runAbysslink(ctx context.Context, binPath string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binPath, args...) //nolint:gosec // conformance harness executes the test subject binary
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// runAbysslinkWithStdin executes the abysslink binary with piped stdin.
func runAbysslinkWithStdin(ctx context.Context, binPath string, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binPath, args...) //nolint:gosec // conformance harness executes the test subject binary
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
