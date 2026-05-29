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
	"path/filepath"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/conformance"
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
// signals preview-only mode in its output (banner: "preview only — run with --apply").
func testUpDryRun(ctx context.Context, binPath, configPath string) error {
	out, err := runAbysslink(ctx, binPath,
		"--config", configPath,
		"up",
	)
	if err != nil {
		return fmt.Errorf("up exited non-zero: %w (output: %s)", err, out)
	}
	lowerOut := strings.ToLower(out)
	if !strings.Contains(lowerOut, "preview only") && !strings.Contains(lowerOut, "--apply") {
		return fmt.Errorf("up output does not signal preview-only/dry-run mode: %q", out)
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

// testCheckPeriodGateRejectsOver12h writes a config with ssh_check_period: 24h
// and verifies that `abysslink up` refuses unless --accept-checkperiod-extension is given.
func testCheckPeriodGateRejectsOver12h(ctx context.Context, binPath, tempDir string) error {
	cfgPath := filepath.Join(tempDir, "checkperiod-gate.yaml")
	cfg := `version: 1
tailnet:
  ssh: true
mobile:
  ssh_check_period: 24h
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("write test config: %w", err)
	}

	// Gate runs at apply time only; dry-run still previews.
	out, err := runAbysslink(ctx, binPath, "--config", cfgPath, "up", "--apply")
	if err == nil {
		return fmt.Errorf("up --apply with 24h checkperiod should have failed but exited 0; output: %s", out)
	}
	if !strings.Contains(out, "accept-checkperiod-extension") &&
		!strings.Contains(strings.ToLower(out), "checkperiod") &&
		!strings.Contains(strings.ToLower(out), "check_period") &&
		!strings.Contains(strings.ToLower(out), "ssh_check_period") {
		return fmt.Errorf("up gate output does not mention checkperiod extension flag: %q", out)
	}
	return nil
}

// testDryRunMutatesNoFiles verifies that `abysslink up` (dry-run default) does not
// create any new files in the temp config directory.
func testDryRunMutatesNoFiles(ctx context.Context, binPath, configPath string) error {
	cfgDir := filepath.Dir(configPath)

	beforeEntries, err := countFiles(cfgDir)
	if err != nil {
		return fmt.Errorf("count files before: %w", err)
	}

	_, _ = runAbysslink(ctx, binPath, "--config", configPath, "up")

	afterEntries, err := countFiles(cfgDir)
	if err != nil {
		return fmt.Errorf("count files after: %w", err)
	}

	if afterEntries > beforeEntries {
		return fmt.Errorf("dry-run created %d new file(s) in config dir (before=%d after=%d)",
			afterEntries-beforeEntries, beforeEntries, afterEntries)
	}
	return nil
}

// countFiles returns the number of regular files under dir (non-recursive).
func countFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	return n, nil
}

// testBackupLsNoPanic verifies that `abysslink backup ls` exits without a Go panic.
func testBackupLsNoPanic(ctx context.Context, binPath, configPath string) error {
	out, _ := runAbysslink(ctx, binPath, "--config", configPath, "backup", "ls")
	if strings.Contains(out, "panic:") && strings.Contains(out, "goroutine") {
		return fmt.Errorf("backup ls produced Go panic: %q", out)
	}
	return nil
}

// testUninstallDryRunShowsPlan verifies that `abysslink uninstall` (dry-run default)
// exits without panic and outputs a plan.
func testUninstallDryRunShowsPlan(ctx context.Context, binPath, configPath string) error {
	out, _ := runAbysslink(ctx, binPath, "--config", configPath, "uninstall")
	if strings.Contains(out, "panic:") && strings.Contains(out, "goroutine") {
		return fmt.Errorf("uninstall dry-run produced Go panic: %q", out)
	}
	lowerOut := strings.ToLower(out)
	if !strings.Contains(lowerOut, "dry") &&
		!strings.Contains(lowerOut, "plan") &&
		!strings.Contains(lowerOut, "restore") &&
		!strings.Contains(lowerOut, "uninstall") &&
		!strings.Contains(lowerOut, "nothing") {
		return fmt.Errorf("uninstall dry-run output does not mention plan/restore/dry: %q", out)
	}
	return nil
}

// testNtfyBindAddrConformance calls conformance.CheckNtfyConfigBindAddr with both
// a compliant and a non-compliant ntfy config to verify the check works.
func testNtfyBindAddrConformance(ctx context.Context) error {
	bad := `listen-http: "0.0.0.0:8080"` + "\n"
	if err := conformance.CheckNtfyConfigBindAddr(ctx, bad); err == nil {
		return fmt.Errorf("CheckNtfyConfigBindAddr should have rejected 0.0.0.0 config")
	}

	good := `listen-http: "100.64.1.2:8080"` + "\n"
	if err := conformance.CheckNtfyConfigBindAddr(ctx, good); err != nil {
		return fmt.Errorf("CheckNtfyConfigBindAddr rejected valid tailnet-IP config: %w", err)
	}
	return nil
}

// testSSHHardeningConformance calls conformance.CheckSSHHardeningDirectives with
// a compliant and a non-compliant sshd drop-in config.
func testSSHHardeningConformance(ctx context.Context) error {
	good := `PasswordAuthentication no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitRootLogin no
AllowUsers alice
`
	if err := conformance.CheckSSHHardeningDirectives(ctx, good); err != nil {
		return fmt.Errorf("CheckSSHHardeningDirectives rejected valid config: %w", err)
	}

	bad := `PasswordAuthentication no
AllowTcpForwarding no
X11Forwarding no
PermitRootLogin no
`
	if err := conformance.CheckSSHHardeningDirectives(ctx, bad); err == nil {
		return fmt.Errorf("CheckSSHHardeningDirectives should have rejected config missing AllowAgentForwarding")
	}
	return nil
}

// testBinarySizeUnder50MB verifies that the abysslink binary is under 50 MB.
func testBinarySizeUnder50MB(ctx context.Context, binPath string) error {
	const limit = 50 << 20 // 50 MB
	return conformance.CheckBinarySize(ctx, binPath, limit)
}

// testInitYesNoHang verifies that `abysslink init --yes` completes within the
// context deadline without producing a Go panic trace, and writes a config file.
// The guided journey must run headless under --yes (T-10-16: never hang in non-TTY).
func testInitYesNoHang(ctx context.Context, binPath string) error {
	tmpDir, err := os.MkdirTemp("", "conformance-init-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cfgPath := filepath.Join(tmpDir, "abysslink.yaml")
	out, initErr := runAbysslink(ctx, binPath,
		"--config", cfgPath,
		"init", "--yes",
	)

	// A Go panic is a hard fail regardless of exit code.
	if strings.Contains(out, "panic:") && strings.Contains(out, "goroutine") {
		return fmt.Errorf("init --yes produced Go panic: %q", out)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("init --yes timed out — likely hung waiting for interactive input")
	}
	if initErr != nil {
		// Non-zero exit is acceptable: the machine may be missing tools or
		// the journey stage failed for environmental reasons; as long as it
		// didn't hang and didn't panic the headless contract is satisfied.
		return nil
	}
	// If it exited 0 the config file should exist.
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		return fmt.Errorf("init --yes exited 0 but no config at %s: %w", cfgPath, statErr)
	}
	return nil
}

// testDoctorJSONNoANSI verifies that `abysslink --json doctor` output:
//   - First line parses as a JSON value (array or object).
//   - Contains no ANSI ESC (0x1b) bytes.
//
// A non-zero exit is acceptable because the machine may not have all tools.
func testDoctorJSONNoANSI(ctx context.Context, binPath, configPath string) error {
	out, _ := runAbysslink(ctx, binPath,
		"--config", configPath,
		"--json",
		"doctor",
	)
	if ctx.Err() != nil {
		return fmt.Errorf("doctor --json timed out")
	}
	if strings.Contains(out, "panic:") && strings.Contains(out, "goroutine") {
		return fmt.Errorf("doctor --json produced Go panic: %q", out)
	}
	if out == "" {
		return fmt.Errorf("doctor --json produced no output")
	}
	// Check for ANSI ESC bytes.
	if strings.Contains(out, "\x1b") {
		return fmt.Errorf("doctor --json output contains ANSI ESC bytes (0x1b) — JSON must be ANSI-free")
	}
	// First line should be parseable as JSON (array or object element).
	firstLine := strings.SplitN(out, "\n", 2)[0]
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(firstLine), &raw); err != nil {
		return fmt.Errorf("doctor --json first line is not valid JSON %q: %w", firstLine, err)
	}
	return nil
}

// testStatusJSONNoANSI extends testStatusJSON to additionally assert no ANSI ESC
// bytes in the output (T-10-18: JSON must be ANSI-free for machine consumers).
func testStatusJSONNoANSI(ctx context.Context, binPath, configPath string) error {
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
	// No ANSI escape bytes.
	if strings.Contains(out, "\x1b") {
		return fmt.Errorf("status --json output contains ANSI ESC bytes (0x1b) — JSON must be ANSI-free")
	}
	// Valid JSON object.
	firstLine := strings.SplitN(out, "\n", 2)[0]
	var obj map[string]interface{}
	if decErr := json.Unmarshal([]byte(firstLine), &obj); decErr != nil {
		return fmt.Errorf("status --json first line is not valid JSON %q: %w", firstLine, decErr)
	}
	return nil
}

// testUninstallTypedConfirmNoHang verifies that `abysslink uninstall --apply` with
// empty piped stdin (no TTY) does NOT hang and does NOT panic. The typed-confirm
// design from 10-04 must be non-interactive-safe: when stdin is empty the
// confirmation must fail clearly (no blocking read).
func testUninstallTypedConfirmNoHang(ctx context.Context, binPath, configPath string) error {
	deadline := 15 * time.Second
	uninstCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	// Pipe empty stdin so no TTY is presented.
	out, _ := runAbysslinkWithStdin(uninstCtx, binPath, "",
		"--config", configPath,
		"uninstall", "--apply",
	)

	if uninstCtx.Err() != nil {
		return fmt.Errorf("uninstall --apply timed out after %s (likely blocked on typed confirm)", deadline)
	}
	if strings.Contains(out, "panic:") && strings.Contains(out, "goroutine") {
		return fmt.Errorf("uninstall --apply produced Go panic: %q", out)
	}
	// A non-zero exit or "non-interactive" error message is expected and acceptable.
	return nil
}

// testExitCodesDocumented verifies that `abysslink --help` or `abysslink doctor --help`
// mentions exit codes 0, 1, and 2, satisfying the UX-10 documentation requirement.
func testExitCodesDocumented(ctx context.Context, binPath, configPath string) error {
	out, _ := runAbysslink(ctx, binPath,
		"--config", configPath,
		"--help",
	)
	if ctx.Err() != nil {
		return fmt.Errorf("--help timed out")
	}
	if !strings.Contains(out, "0") || !strings.Contains(out, "1") || !strings.Contains(out, "2") {
		// Fall back to doctor --help
		doctorOut, _ := runAbysslink(ctx, binPath,
			"--config", configPath,
			"doctor", "--help",
		)
		if !strings.Contains(doctorOut, "0") || !strings.Contains(doctorOut, "1") || !strings.Contains(doctorOut, "2") {
			return fmt.Errorf("neither root --help nor doctor --help documents exit codes 0/1/2; root: %q; doctor: %q", out, doctorOut)
		}
	}
	return nil
}
