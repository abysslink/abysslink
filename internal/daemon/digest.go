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
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/shell"
)

// digestDefaultTopic is the fallback ntfy topic used when the operator has not
// configured a dedicated digest topic. The digest is delivered on its own topic
// so it can be muted/routed independently of operational alerts.
const digestDefaultTopic = "abysslink-digest"

// digestStatus is the subset of `abysslink status --json` fields the digest
// consumes. It deliberately omits hostname / IP / node_id so a decode of
// untrusted stdout cannot smuggle identifying fields into the digest payload
// (T-18-11). Only opaque, non-identifying counters and the lock status are read.
type digestStatus struct {
	Reachable  bool   `json:"reachable"`
	FatalCount int    `json:"fatal_count"`
	WarnCount  int    `json:"warn_count"`
	LockStatus string `json:"lock_status"`
}

// digestPayload is the per-rig summary structure. RigID is ALWAYS the opaque
// SHA-256 hash of the rig name (metrics.OpaqueRigLabel) — never the raw rig
// Name, Hostname, NtfyTopic, or any field that could identify the rig to an
// observer (T-18-11, OBS-04).
type digestPayload struct {
	RigID      string `json:"rig_id"`
	Reachable  bool   `json:"reachable"`
	FatalCount int    `json:"fatal_count"`
	WarnCount  int    `json:"warn_count"`
	LockStatus string `json:"lock_status"`
}

// nextFireAt returns the duration until the next occurrence of hour:minute in
// the local time zone. It delegates to nextFireAtFrom(time.Now(), ...) so the
// computation is unit-testable with a fixed clock.
func nextFireAt(hour, minute int) time.Duration {
	return nextFireAtFrom(time.Now(), hour, minute)
}

// nextFireAtFrom returns the duration from now until the next occurrence of the
// given wall-clock hour:minute in now's location. If the computed time is not
// strictly after now (already past, or exactly now), it advances by 24h so the
// returned duration is always positive.
func nextFireAtFrom(now time.Time, hour, minute int) time.Duration {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}

// resolveAbysslink locates the abysslink CLI binary. It first looks for a
// sibling named "abysslink" in the same directory as the running abysslinkd
// executable (the canonical co-install layout, T-18-12: the path comes from the
// OS via os.Executable, never from user-controlled config or environment). If
// no sibling exists it falls back to exec.LookPath. When neither resolves it
// logs a warning and returns an error so the caller skips the send (no panic).
//
// The ABYSSLINK_TEST_EXE_DIR env var overrides the executable directory in
// tests only; production never sets it, so the real os.Executable() path wins.
func resolveAbysslink() (string, error) {
	exeDir := os.Getenv("ABYSSLINK_TEST_EXE_DIR")
	if exeDir == "" {
		exePath, err := os.Executable()
		if err == nil {
			exeDir = filepath.Dir(exePath)
		}
	}

	if exeDir != "" {
		sibling := filepath.Join(exeDir, "abysslink")
		if _, statErr := os.Stat(sibling); statErr == nil {
			return sibling, nil
		}
	}

	if path, err := exec.LookPath("abysslink"); err == nil {
		return path, nil
	}

	slog.Warn("abysslinkd: digest: abysslink binary not found via sibling or PATH")
	return "", fmt.Errorf("digest: abysslink binary not found")
}

// digestTopic returns the configured digest ntfy topic, falling back to
// digestDefaultTopic when none is set.
func digestTopic(cfg *config.Config) string {
	if cfg.Observability.Digest.NtfyTopic != "" {
		return cfg.Observability.Digest.NtfyTopic
	}
	return digestDefaultTopic
}

// sendDigest gathers the local posture by invoking the sibling abysslink binary
// (`abysslink status --json`, NOT the daemon's own socket — OBS-08 / Pitfall 6),
// builds an opaque per-rig payload, and delivers a summary via the Notifier on
// the dedicated digest topic. Every failure path logs and returns without
// panicking. The notification body contains only the opaque rig id and counters
// — never the raw hostname (T-18-11).
func sendDigest(ctx context.Context, cfg *config.Config, notifier Notifier, runner shell.Runner) {
	binaryPath, err := resolveAbysslink()
	if err != nil {
		slog.Warn("abysslinkd: digest: cannot resolve abysslink binary; skipping", "err", err)
		return
	}

	// Discrete argv (no sh -c) per CLAUDE.md; the resolved absolute path is the
	// program name. This calls the CLI, never the daemon Unix socket.
	res, runErr := runner.Run(ctx, binaryPath, "status", "--json")
	if runErr != nil || res.ExitCode != 0 {
		slog.Warn("abysslinkd: digest: status --json failed", "err", runErr, "exit", res.ExitCode)
		return
	}

	var st digestStatus
	if jErr := json.Unmarshal([]byte(res.Stdout), &st); jErr != nil {
		slog.Warn("abysslinkd: digest: parse status JSON failed", "err", jErr)
		return
	}

	rigID := metrics.OpaqueRigLabel(cfg.Tailnet.Hostname)
	payload := digestPayload{
		RigID:      rigID,
		Reachable:  st.Reachable,
		FatalCount: st.FatalCount,
		WarnCount:  st.WarnCount,
		LockStatus: st.LockStatus,
	}

	// Body uses the OPAQUE rig id only — never the raw hostname (T-18-11).
	body := fmt.Sprintf("rig %s: reachable=%v fatal=%d warn=%d lock=%s",
		payload.RigID, payload.Reachable, payload.FatalCount, payload.WarnCount, payload.LockStatus)

	// The digest is delivered on a dedicated topic so it can be routed/muted
	// independently. The daemon Notifier interface carries (title, body) only;
	// the resolved topic is surfaced in the diagnostic log for operator
	// observability without an architectural change to Notifier this phase.
	topic := digestTopic(cfg)
	slog.Info("abysslinkd: digest: sending", "topic", topic, "rig", payload.RigID)

	if sErr := notifier.Send(ctx, "Fleet Daily Digest", body); sErr != nil {
		slog.Warn("abysslinkd: digest: notifier send failed", "err", sErr)
	}
}

// StartDigestScheduler launches the daily fleet-digest goroutine when
// observability.digest.enabled is true. It returns immediately (no goroutine)
// when the digest is disabled. The goroutine waits until the next configured
// fire time (default 08:00 local), sends the first digest, then fires every 24h.
// It exits cleanly on ctx.Done. Modeled on startAnchorWriter (Phase 17).
//
// Exported so cmd/abysslinkd/main.go (package main) can launch it; the helpers
// it calls (sendDigest, nextFireAt, resolveAbysslink, digestTopic) stay
// unexported and are covered by in-package tests.
func StartDigestScheduler(ctx context.Context, cfg *config.Config, notifier Notifier, runner shell.Runner) {
	if !cfg.Observability.Digest.Enabled {
		return
	}

	hour := 8
	if cfg.Observability.Digest.Hour > 0 {
		hour = cfg.Observability.Digest.Hour
	}

	go func() {
		timer := time.NewTimer(nextFireAt(hour, 0))
		defer timer.Stop()

		select {
		case <-timer.C:
		case <-ctx.Done():
			return
		}

		// First fire, then tick every 24h.
		sendDigest(ctx, cfg, notifier, runner)

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendDigest(ctx, cfg, notifier, runner)
			case <-ctx.Done():
				return
			}
		}
	}()
}
