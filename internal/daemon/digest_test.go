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

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// digestNotifier captures the last Send title/body for assertions.
type digestNotifier struct {
	title  string
	body   string
	called bool
	err    error
}

func (n *digestNotifier) Send(_ context.Context, title, body string) error {
	n.called = true
	n.title = title
	n.body = body
	return n.err
}

func TestStartDigestSchedulerDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Observability.Digest.Enabled = false

	notifier := &digestNotifier{}
	runner := shell.NewMockRunner() // no scripted calls — any call would error

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Must return immediately and launch no goroutine that fires sendDigest.
	StartDigestScheduler(ctx, cfg, notifier, runner)
	time.Sleep(20 * time.Millisecond)

	assert.False(t, notifier.called, "disabled digest must never call Send")
}

func TestNextFireAt_AfterNow(t *testing.T) {
	// At 07:55 local, the next 08:00 should be a small positive duration < 6m.
	now := time.Date(2026, 6, 2, 7, 55, 0, 0, time.Local)
	d := nextFireAtFrom(now, 8, 0)
	assert.Greater(t, d, time.Duration(0))
	assert.Less(t, d, 6*time.Minute)
}

func TestNextFireAt_BeforeNow(t *testing.T) {
	// At 09:00 local (past 08:00), next fire is ~23h away (next day).
	now := time.Date(2026, 6, 2, 9, 0, 0, 0, time.Local)
	d := nextFireAtFrom(now, 8, 0)
	assert.InDelta(t, 23*time.Hour, d, float64(time.Minute))
}

func TestNextFireAt_Exact(t *testing.T) {
	// At exactly 08:00:00, next fire is ~24h (not zero, not negative).
	now := time.Date(2026, 6, 2, 8, 0, 0, 0, time.Local)
	d := nextFireAtFrom(now, 8, 0)
	assert.InDelta(t, 24*time.Hour, d, float64(time.Minute))
	assert.Greater(t, d, time.Duration(0))
}

// TestDigestHour is the NET-16 regression: an explicit hour: 0 (midnight)
// must be honored, not silently replaced by the 08:00 default. nil (unset)
// and out-of-range values fall back to 08:00.
func TestDigestHour(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	cfg := config.Defaults()
	assert.Equal(t, 8, digestHour(cfg), "unset hour (nil) defaults to 08:00")

	cfg.Observability.Digest.Hour = intPtr(0)
	assert.Equal(t, 0, digestHour(cfg), "explicit hour: 0 (midnight) must be honored (NET-16)")

	cfg.Observability.Digest.Hour = intPtr(17)
	assert.Equal(t, 17, digestHour(cfg))

	cfg.Observability.Digest.Hour = intPtr(24)
	assert.Equal(t, 8, digestHour(cfg), "out-of-range hour falls back to the default")

	cfg.Observability.Digest.Hour = intPtr(-1)
	assert.Equal(t, 8, digestHour(cfg), "negative hour falls back to the default")
}

func TestSendDigestRunner(t *testing.T) {
	cfg := config.Defaults()
	cfg.Tailnet.Hostname = "my-laptop"
	cfg.Observability.Digest.NtfyTopic = "abysslink-digest-xyz"

	// Provide a valid sibling abysslink binary so resolveAbysslink succeeds.
	dir := t.TempDir()
	writeFakeBinary(t, filepath.Join(dir, "abysslink"))
	t.Setenv("ABYSSLINK_TEST_EXE_DIR", dir)

	statusJSON := `{"reachable":true,"fatal_count":0,"warn_count":1,"lock_status":"enabled"}`
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: statusJSON, ExitCode: 0}})
	notifier := &digestNotifier{}

	sendDigest(context.Background(), cfg, notifier, runner)

	calls := runner.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].Args, "status")
	assert.Contains(t, calls[0].Args, "--json")
	// Must NOT dial the daemon socket: the binary name is the resolved abysslink path.
	assert.NotContains(t, calls[0].Name, "sock")
	assert.True(t, notifier.called)
}

func TestSendDigestOpaque(t *testing.T) {
	cfg := config.Defaults()
	cfg.Tailnet.Hostname = "secret-hostname-rig"

	dir := t.TempDir()
	writeFakeBinary(t, filepath.Join(dir, "abysslink"))
	t.Setenv("ABYSSLINK_TEST_EXE_DIR", dir)

	statusJSON := `{"reachable":true,"fatal_count":2,"warn_count":0,"lock_status":"enabled"}`
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: statusJSON, ExitCode: 0}})
	notifier := &digestNotifier{}

	sendDigest(context.Background(), cfg, notifier, runner)

	require.True(t, notifier.called)
	// Raw hostname must never appear in the notification body — only the opaque hash.
	assert.NotContains(t, notifier.body, "secret-hostname-rig")
	assert.Contains(t, notifier.body, metrics.OpaqueRigLabel("secret-hostname-rig"))
}

func TestSendDigestTopicFallback(t *testing.T) {
	cfg := config.Defaults()
	cfg.Tailnet.Hostname = "rig1"
	cfg.Observability.Digest.NtfyTopic = "" // empty → fallback

	dir := t.TempDir()
	writeFakeBinary(t, filepath.Join(dir, "abysslink"))
	t.Setenv("ABYSSLINK_TEST_EXE_DIR", dir)

	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"reachable":true}`, ExitCode: 0}})
	notifier := &digestNotifier{}

	// digestTopic resolves the fallback when NtfyTopic is empty.
	assert.Equal(t, "abysslink-digest", digestTopic(cfg))

	sendDigest(context.Background(), cfg, notifier, runner)
	assert.True(t, notifier.called)
}

func TestResolveAbysslink_SiblingExists(t *testing.T) {
	dir := t.TempDir()
	sibling := filepath.Join(dir, "abysslink")
	writeFakeBinary(t, sibling)
	t.Setenv("ABYSSLINK_TEST_EXE_DIR", dir)

	got, err := resolveAbysslink()
	require.NoError(t, err)
	assert.Equal(t, sibling, got)
}

func TestResolveAbysslink_Fallback(t *testing.T) {
	// Empty dir → no sibling. resolveAbysslink falls back to PATH; with abysslink
	// absent from PATH this returns an error. We make a PATH entry to exercise the
	// fallback success path deterministically.
	exeDir := t.TempDir()
	t.Setenv("ABYSSLINK_TEST_EXE_DIR", exeDir) // no sibling here

	pathDir := t.TempDir()
	writeFakeBinary(t, filepath.Join(pathDir, "abysslink"))
	t.Setenv("PATH", pathDir)

	got, err := resolveAbysslink()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(pathDir, "abysslink"), got)
}

// writeFakeBinary creates an executable placeholder file at path.
func writeFakeBinary(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755)) //nolint:gosec // G306: test writes an executable shell fixture requiring 0o755
}

// ensure strings is used even if assertions change.
var _ = strings.Contains
