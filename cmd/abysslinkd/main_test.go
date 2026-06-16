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
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bbolt "go.etcd.io/bbolt"

	"github.com/abysslink/abysslink/internal/push"
)

// TestParseArgs_HelpExitsZeroWithoutStarting covers the UX-critical finding:
// `abysslinkd --help` must print usage and exit 0 — never load config, open
// the notify socket, probe tmux, or POST to ntfy.
func TestParseArgs_HelpExitsZeroWithoutStarting(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code, proceed := parseArgs([]string{flag}, &out, &errOut)
			if proceed {
				t.Fatalf("%s must not proceed to daemon startup", flag)
			}
			if code != 0 {
				t.Fatalf("%s must exit 0, got %d", flag, code)
			}
			if !strings.Contains(out.String(), "abysslinkd") || !strings.Contains(out.String(), "Usage:") {
				t.Fatalf("%s must print usage to stdout, got: %q", flag, out.String())
			}
		})
	}
}

// TestParseArgs_VersionExitsZero: --version prints the version and exits 0.
func TestParseArgs_VersionExitsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	code, proceed := parseArgs([]string{"--version"}, &out, &errOut)
	if proceed {
		t.Fatal("--version must not proceed to daemon startup")
	}
	if code != 0 {
		t.Fatalf("--version must exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "abysslinkd") || !strings.Contains(out.String(), version) {
		t.Fatalf("--version must print the version, got: %q", out.String())
	}
}

// TestParseArgs_UnknownFlagExitsTwo: unknown flags error with usage, exit 2.
func TestParseArgs_UnknownFlagExitsTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	code, proceed := parseArgs([]string{"--bogus"}, &out, &errOut)
	if proceed {
		t.Fatal("an unknown flag must not start the daemon")
	}
	if code != 2 {
		t.Fatalf("unknown flag must exit 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "bogus") {
		t.Fatalf("error output must name the bad flag, got: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Fatalf("error output must include usage, got: %q", errOut.String())
	}
}

// TestParseArgs_PositionalArgExitsTwo: stray positional args error, exit 2.
func TestParseArgs_PositionalArgExitsTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	code, proceed := parseArgs([]string{"start"}, &out, &errOut)
	if proceed {
		t.Fatal("a positional arg must not start the daemon")
	}
	if code != 2 {
		t.Fatalf("positional arg must exit 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), `"start"`) {
		t.Fatalf("error output must name the bad arg, got: %q", errOut.String())
	}
}

// TestStartDedupSweeper_SweepsPeriodically closes the T-29-01-5 / T-29-04-3
// gap: the dedup TTL never deletes expired bbolt keys on its own — only
// SweepDedup does — so the steady-state daemon needs a periodic sweep, not just
// the boot sweep. This verifies the goroutine fires SweepDedup on its tick
// (reclaiming an expired entry) and exits on ctx cancellation.
func TestStartDedupSweeper_SweepsPeriodically(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "outbox.db")
	db, err := bbolt.Open(dbPath, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	defer func() { _ = db.Close() }()
	outbox := push.NewOutbox(db)

	// Seed an already-expired dedup entry and a live one.
	if err := outbox.MarkSeen("msg-expired", -time.Second); err != nil {
		t.Fatalf("MarkSeen expired: %v", err)
	}
	if err := outbox.MarkSeen("msg-live", time.Hour); err != nil {
		t.Fatalf("MarkSeen live: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Short interval so the sweep fires promptly under test.
	startDedupSweeper(ctx, outbox, 5*time.Millisecond)

	// Poll until the expired entry is reclaimed by a sweep tick.
	deadline := time.Now().Add(2 * time.Second)
	for {
		seen, derr := outbox.DedupSeen("msg-expired")
		if derr != nil {
			t.Fatalf("DedupSeen: %v", derr)
		}
		if !seen {
			break // swept
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic sweep never reclaimed the expired dedup entry")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The live entry must survive the sweep.
	live, derr := outbox.DedupSeen("msg-live")
	if derr != nil {
		t.Fatalf("DedupSeen live: %v", derr)
	}
	if !live {
		t.Fatal("live dedup entry must survive the periodic sweep")
	}

	// Cancelling ctx must stop the goroutine cleanly (no panic, no hang).
	cancel()
}

// TestParseArgs_NoArgsProceeds: a bare invocation proceeds to daemon startup.
func TestParseArgs_NoArgsProceeds(t *testing.T) {
	var out, errOut bytes.Buffer
	code, proceed := parseArgs(nil, &out, &errOut)
	if !proceed {
		t.Fatal("no args must proceed to daemon startup")
	}
	if code != 0 {
		t.Fatalf("no args exit code must be 0, got %d", code)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("no args must print nothing, got out=%q err=%q", out.String(), errOut.String())
	}
}
