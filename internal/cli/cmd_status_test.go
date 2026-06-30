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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── TestStatusAllRigs ─────────────────────────────────────────────────────────

// statusHostnameRunner is a shell.Runner that dispatches Run results by SSH
// hostname argument (args[0]). Concurrent-safe; avoids MockRunner's sequential
// ordering assumption (same pattern used in fleet/fanout_test.go).
type statusHostnameRunner struct {
	responses map[string]struct {
		res shell.Result
		err error
	}
}

func newStatusHostnameRunner(m map[string]struct {
	res shell.Result
	err error
}) *statusHostnameRunner {
	return &statusHostnameRunner{responses: m}
}

func (h *statusHostnameRunner) Run(_ context.Context, _ string, args ...string) (shell.Result, error) {
	hostname := ""
	if len(args) > 0 {
		hostname = args[0]
	}
	if v, ok := h.responses[hostname]; ok {
		return v.res, v.err
	}
	return shell.Result{ExitCode: 1}, fmt.Errorf("statusHostnameRunner: unexpected hostname %q", hostname)
}

func (h *statusHostnameRunner) RunWithStdin(_ context.Context, _ io.Reader, _ string, args ...string) (shell.Result, error) {
	return h.Run(context.Background(), "", args...)
}

func (h *statusHostnameRunner) RunInteractive(_ context.Context, _ string, _ ...string) error {
	return nil
}

func (h *statusHostnameRunner) RunWithEnv(_ context.Context, _ map[string]string, _ string, args ...string) (shell.Result, error) {
	return h.Run(context.Background(), "", args...)
}

func (h *statusHostnameRunner) RunStream(_ context.Context, _ string, _ ...string) (*shell.Stream, error) {
	return nil, errors.New("runstream: not supported by this fake")
}

// onlineStatusJSON returns the JSON that a real `abysslink status --json` would
// emit for an online rig.
func onlineStatusJSON(t *testing.T, rigName string) string {
	t.Helper()
	rep := statusReport{
		RigName:      rigName,
		Tailscale:    "running",
		TailscaleIP:  "100.100.0.1",
		Hostname:     rigName + ".ts.net",
		TailscaleSSH: "enabled",
		TailnetLock:  "enabled",
		Ntfy:         "enabled",
		DiskEncrypt:  "encrypted",
		Timestamp:    "2026-06-01 12:00",
	}
	b, err := json.Marshal(rep)
	require.NoError(t, err)
	return string(b)
}

// TestStatusAllRigs verifies the --all-rigs fan-out: one online rig and one
// offline rig. The offline rig must appear as UNREACHABLE and the command exits
// 0 (SC-2). Online rig carries rig_name. (Plan 14-05 Task 1 acceptance criterion)
func TestStatusAllRigs(t *testing.T) {
	const (
		onlineRig  = "alpha"
		offlineRig = "beta"
	)

	onlineJSON := onlineStatusJSON(t, onlineRig)

	runner := newStatusHostnameRunner(map[string]struct {
		res shell.Result
		err error
	}{
		onlineRig + ".example.ts.net":  {res: shell.Result{ExitCode: 0, Stdout: onlineJSON}},
		offlineRig + ".example.ts.net": {res: shell.Result{ExitCode: 1}, err: errors.New("unreachable")},
	})

	cfg := config.Defaults()
	cfg.Rigs = []config.RigConfig{
		{Name: onlineRig, Hostname: onlineRig + ".example.ts.net"},
		{Name: offlineRig, Hostname: offlineRig + ".example.ts.net"},
	}

	cc := &cmdContext{
		cfg:     cfg,
		runner:  runner,
		jsonOut: false,
	}

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)

	err := statusRigs(context.Background(), cc, p, false /* strict=false */, cc.cfg.Rigs)
	assert.NoError(t, err, "exit 0 when strict=false even with an offline rig (SC-2)")

	output := out.String()
	assert.Contains(t, output, onlineRig, "online rig name must appear in output")
	assert.Contains(t, output, "UNREACHABLE", "offline rig must show UNREACHABLE")
}

// TestStatusAllRigs_Strict verifies that --strict drives exit 1 when any rig is
// UNREACHABLE (plan acceptance criterion for --strict behavior).
func TestStatusAllRigs_Strict(t *testing.T) {
	const offlineRig = "gamma"

	runner := newStatusHostnameRunner(map[string]struct {
		res shell.Result
		err error
	}{
		offlineRig + ".example.ts.net": {res: shell.Result{ExitCode: 1}, err: errors.New("timeout")},
	})

	cfg := config.Defaults()
	cfg.Rigs = []config.RigConfig{
		{Name: offlineRig, Hostname: offlineRig + ".example.ts.net"},
	}

	cc := &cmdContext{
		cfg:     cfg,
		runner:  runner,
		jsonOut: false,
	}

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)

	err := statusRigs(context.Background(), cc, p, true /* strict=true */, cc.cfg.Rigs)
	var ee *exitError
	assert.True(t, errors.As(err, &ee), "strict+unreachable must return exitError")
	if ee != nil {
		assert.Equal(t, exitCodeFatal, ee.code, "exit code must be fatal (2) under --strict")
	}
}

// TestStatusAllRigs_JSON verifies that --json produces an ANSI-free JSON array
// where each element has a rig_name field (UX-04, plan acceptance criterion).
func TestStatusAllRigs_JSON(t *testing.T) {
	const onlineRig = "delta"
	onlineJSON := onlineStatusJSON(t, onlineRig)

	runner := newStatusHostnameRunner(map[string]struct {
		res shell.Result
		err error
	}{
		onlineRig + ".example.ts.net": {res: shell.Result{ExitCode: 0, Stdout: onlineJSON}},
	})

	cfg := config.Defaults()
	cfg.Rigs = []config.RigConfig{
		{Name: onlineRig, Hostname: onlineRig + ".example.ts.net"},
	}

	cc := &cmdContext{
		cfg:     cfg,
		runner:  runner,
		jsonOut: true,
	}

	var out bytes.Buffer
	p := NewJSONPrinterTo(&out, io.Discard)

	err := statusRigs(context.Background(), cc, p, false, cc.cfg.Rigs)
	assert.NoError(t, err)

	output := out.String()
	var aggregate []statusReport
	require.NoError(t, json.Unmarshal([]byte(output), &aggregate), "output must be a valid JSON array")
	require.Len(t, aggregate, 1, "one rig => one element")
	assert.Equal(t, onlineRig, aggregate[0].RigName, "rig_name must be set in JSON output")
}

// ── TestPanicAllRigs ──────────────────────────────────────────────────────────

// TestPanicAllRigs verifies that panicAllRigs fans out with the 10s per-rig
// budget (SC-3) and does not crash when a rig is UNREACHABLE (best-effort contract).
func TestPanicAllRigs(t *testing.T) {
	const (
		onlineRig  = "epsilon"
		offlineRig = "zeta"
	)

	runner := newStatusHostnameRunner(map[string]struct {
		res shell.Result
		err error
	}{
		onlineRig + ".example.ts.net":  {res: shell.Result{ExitCode: 0, Stdout: ""}},
		offlineRig + ".example.ts.net": {res: shell.Result{ExitCode: 1}, err: errors.New("no route to host")},
	})

	cfg := config.Defaults()
	cfg.Rigs = []config.RigConfig{
		{Name: onlineRig, Hostname: onlineRig + ".example.ts.net"},
		{Name: offlineRig, Hostname: offlineRig + ".example.ts.net"},
	}

	cc := &cmdContext{cfg: cfg, runner: runner}

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)

	// strict=false: UNREACHABLE rig must NOT cause a panic or fatal error.
	err := panicAllRigs(context.Background(), cc, p, false)
	assert.NoError(t, err, "panicAllRigs must not crash or error when strict=false and a rig is offline")

	output := out.String()
	assert.Contains(t, output, offlineRig, "offline rig name must appear in panic output")
	assert.Contains(t, output, "UNREACHABLE", "offline rig must show UNREACHABLE in panic output")
}

// TestPanicAllRigs_Strict verifies that --strict causes panicAllRigs to return
// a non-nil error when any rig is UNREACHABLE.
func TestPanicAllRigs_Strict(t *testing.T) {
	const offlineRig = "eta"

	runner := newStatusHostnameRunner(map[string]struct {
		res shell.Result
		err error
	}{
		offlineRig + ".example.ts.net": {res: shell.Result{ExitCode: 1}, err: errors.New("timeout")},
	})

	cfg := config.Defaults()
	cfg.Rigs = []config.RigConfig{
		{Name: offlineRig, Hostname: offlineRig + ".example.ts.net"},
	}

	cc := &cmdContext{cfg: cfg, runner: runner}

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)

	err := panicAllRigs(context.Background(), cc, p, true /* strict=true */)
	assert.Error(t, err, "panicAllRigs must return error when strict=true and a rig is offline")
}
