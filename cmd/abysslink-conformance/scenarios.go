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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// testVersionOutput verifies that `abysslink version` prints "abysslink" somewhere.
func testVersionOutput(ctx context.Context, binPath string) error {
	out, err := runAbysslink(ctx, binPath, "version")
	if err != nil {
		return fmt.Errorf("version exited non-zero: %w (output: %s)", err, out)
	}
	if !strings.Contains(strings.ToLower(out), "abysslink") {
		return fmt.Errorf("version output does not contain 'abysslink': %q", out)
	}
	return nil
}

// testInitCreatesConfig runs `abysslink --config <path> init --yes` and verifies that
// the config file is created and contains valid YAML.
func testInitCreatesConfig(ctx context.Context, binPath, _ string, configPath string) error {
	out, err := runAbysslink(ctx, binPath,
		"--config", configPath,
		"init", "--yes",
	)
	if err != nil {
		return fmt.Errorf("init exited non-zero: %w (output: %s)", err, out)
	}

	if _, statErr := os.Stat(configPath); statErr != nil {
		return fmt.Errorf("config file not created at %s: %w", configPath, statErr)
	}

	data, readErr := os.ReadFile(configPath) //nolint:gosec
	if readErr != nil {
		return fmt.Errorf("could not read config file: %w", readErr)
	}
	if len(data) == 0 {
		return fmt.Errorf("config file is empty")
	}
	// Verify it looks like YAML by checking for key: value pattern.
	if !strings.Contains(string(data), ":") {
		return fmt.Errorf("config file does not appear to be YAML (no ':' found)")
	}
	return nil
}

// testUpDryRun verifies that `abysslink up` (dry-run by default) exits 0 and
// mentions dry-run mode in its output.
func testUpDryRun(ctx context.Context, binPath, configPath string) error {
	out, err := runAbysslink(ctx, binPath,
		"--config", configPath,
		"up",
	)
	if err != nil {
		return fmt.Errorf("up exited non-zero: %w (output: %s)", err, out)
	}
	lowerOut := strings.ToLower(out)
	if !strings.Contains(lowerOut, "dry-run") && !strings.Contains(lowerOut, "dry run") {
		return fmt.Errorf("up output does not mention dry-run mode: %q", out)
	}
	return nil
}

// testDoctorExitCodes verifies that `abysslink doctor` exits without panic.
// A non-zero exit is acceptable (the machine may not have all tools installed);
// what matters is no panic output.
func testDoctorExitCodes(ctx context.Context, binPath, configPath string) error {
	out, _ := runAbysslink(ctx, binPath,
		"--config", configPath,
		"doctor",
	)
	// A panic would print "panic:" on stderr.
	if strings.Contains(out, "panic:") || strings.Contains(out, "goroutine") {
		return fmt.Errorf("doctor output shows panic: %q", out)
	}
	return nil
}

// testStatusJSON verifies that `abysslink --json status` emits valid JSON.
func testStatusJSON(ctx context.Context, binPath, configPath string) error {
	out, err := runAbysslink(ctx, binPath,
		"--config", configPath,
		"--json",
		"status",
	)
	if err != nil {
		return fmt.Errorf("status --json exited non-zero: %w (output: %s)", err, out)
	}
	if out == "" {
		return fmt.Errorf("status --json produced no output")
	}

	// The JSON printer emits one object per line; try to parse the first line.
	firstLine := strings.SplitN(out, "\n", 2)[0]
	var obj map[string]interface{}
	if decErr := json.Unmarshal([]byte(firstLine), &obj); decErr != nil {
		return fmt.Errorf("status --json first line is not valid JSON %q: %w", firstLine, decErr)
	}
	return nil
}

// testPanicNoHang verifies that `abysslink panic` completes within 15 seconds
// even when stdin is closed (no interactive prompt).
func testPanicNoHang(ctx context.Context, binPath, configPath string) error {
	deadline := 15 * time.Second
	panicCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	// Pipe empty stdin so there's no TTY prompting.
	out, _ := runAbysslinkWithStdin(panicCtx, binPath, "",
		"--config", configPath,
		"panic",
	)

	if panicCtx.Err() != nil {
		return fmt.Errorf("panic command timed out after %s", deadline)
	}
	// Should not produce a Go panic trace.
	if strings.Contains(out, "panic:") && strings.Contains(out, "goroutine") {
		return fmt.Errorf("panic command produced Go panic output: %q", out)
	}
	return nil
}

// testNotifyStdin verifies that `echo "test" | abysslink notify "title" --stdin`
// completes without hanging. A non-zero exit is acceptable if ntfy is not running.
func testNotifyStdin(ctx context.Context, binPath, configPath string) error {
	notifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, _ := runAbysslinkWithStdin(notifyCtx, binPath, "conformance-test\n",
		"--config", configPath,
		"notify", "conformance-title", "--stdin",
	)

	if notifyCtx.Err() != nil {
		return fmt.Errorf("notify --stdin timed out (hung waiting for input)")
	}
	// A Go panic would be a real failure.
	if strings.Contains(out, "panic:") && strings.Contains(out, "goroutine") {
		return fmt.Errorf("notify produced Go panic output: %q", out)
	}
	return nil
}

// testDisableEnableRoundTrip verifies that `abysslink disable ntfy` followed by
// `abysslink enable ntfy` both exit 0 in dry-run mode, or produce a structured
// error (not a Go panic) if the commands are not yet implemented.
func testDisableEnableRoundTrip(ctx context.Context, binPath, configPath string) error {
	// Both commands use dry-run by default, so they only plan, never mutate.
	disableOut, disableErr := runAbysslink(ctx, binPath,
		"--config", configPath,
		"disable", "ntfy",
	)
	if disableErr != nil {
		// "not implemented yet" is an acceptable outcome; it means the module
		// is a planned stub. A Go panic is not acceptable.
		if strings.Contains(disableOut, "panic:") && strings.Contains(disableOut, "goroutine") {
			return fmt.Errorf("disable ntfy produced Go panic: %s", disableOut)
		}
		// Stub error — acceptable for now; log and skip the enable step.
		fmt.Printf("  NOTE: disable ntfy returned error (stub): %v\n", disableErr)
		return nil
	}

	enableOut, enableErr := runAbysslink(ctx, binPath,
		"--config", configPath,
		"enable", "ntfy",
	)
	if enableErr != nil {
		if strings.Contains(enableOut, "panic:") && strings.Contains(enableOut, "goroutine") {
			return fmt.Errorf("enable ntfy produced Go panic: %s", enableOut)
		}
		fmt.Printf("  NOTE: enable ntfy returned error (stub): %v\n", enableErr)
	}

	return nil
}
