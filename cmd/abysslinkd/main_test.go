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
	"strings"
	"testing"
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
