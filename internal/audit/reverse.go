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

package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ReadLog parses the audit log at logPath into Entry records. A missing log is
// not an error — it returns an empty slice.
func ReadLog(logPath string) ([]Entry, error) {
	f, err := os.Open(logPath) //nolint:gosec // logPath is an internal, app-controlled path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open log %s: %w", logPath, err)
	}
	defer f.Close() //nolint:errcheck

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("audit: parse log line: %w", err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: read log %s: %w", logPath, err)
	}
	return entries, nil
}

// MutatedTargets returns the distinct file paths abysslink has written (op
// "write", non-dry-run), in first-seen order.
func MutatedTargets(logPath string) ([]string, error) {
	entries, err := ReadLog(logPath)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var targets []string
	for _, e := range entries {
		if e.Op != "write" || e.DryRun {
			continue
		}
		if !seen[e.Target] {
			seen[e.Target] = true
			targets = append(targets, e.Target)
		}
	}
	return targets, nil
}

// Backups returns the backup files for target (the <target>.bak.<timestamp>
// sidecars), sorted oldest-first. The timestamp format sorts chronologically by
// lexical order, so index 0 is the earliest (pre-abysslink) content.
func Backups(target string) ([]string, error) {
	matches, err := filepath.Glob(target + ".bak.*")
	if err != nil {
		return nil, fmt.Errorf("audit: glob backups for %s: %w", target, err)
	}
	sort.Strings(matches)
	return matches, nil
}

// ReverseAction records what reversing a single mutated target did (or would do).
type ReverseAction struct {
	Target string
	Action string // "restore" | "delete" | "skip"
	Backup string // backup file used for a restore (empty otherwise)
	Hash   string // SHA-256 of the file content after the action ("" if removed/absent)
	Err    error  // non-nil if the action failed
}

// PlanReverse computes how to undo every mutation in the audit log: a target
// with a backup is restored to its earliest (pre-abysslink) content; a target
// abysslink created (no backup) is deleted; an already-absent target is skipped.
func PlanReverse(logPath string) ([]ReverseAction, error) {
	targets, err := MutatedTargets(logPath)
	if err != nil {
		return nil, err
	}

	plan := make([]ReverseAction, 0, len(targets))
	for _, t := range targets {
		baks, _ := Backups(t)
		switch {
		case len(baks) > 0:
			plan = append(plan, ReverseAction{Target: t, Action: "restore", Backup: baks[0]})
		default:
			if _, statErr := os.Stat(t); statErr == nil {
				plan = append(plan, ReverseAction{Target: t, Action: "delete"})
			} else {
				plan = append(plan, ReverseAction{Target: t, Action: "skip"})
			}
		}
	}
	return plan, nil
}

// Reverse undoes every mutation recorded in the audit log. When dryRun is true
// it computes the plan and the resulting hashes without touching the
// filesystem. On a real run it restores or deletes each target and removes the
// now-redundant sidecar backups, returning a manifest of what happened. Errors
// on individual targets are recorded per-action; the overall walk continues.
func Reverse(logPath string, dryRun bool) ([]ReverseAction, error) {
	plan, err := PlanReverse(logPath)
	if err != nil {
		return nil, err
	}

	for i := range plan {
		a := &plan[i]
		switch a.Action {
		case "restore":
			if dryRun {
				if content, rerr := os.ReadFile(a.Backup); rerr == nil { //nolint:gosec
					a.Hash = HashOf(content)
				}
				continue
			}
			if rerr := Restore(a.Target, a.Backup); rerr != nil {
				a.Err = rerr
				continue
			}
			if content, rerr := os.ReadFile(a.Target); rerr == nil { //nolint:gosec
				a.Hash = HashOf(content)
			}
			// The original content is back in place; drop the redundant backups.
			if baks, gerr := Backups(a.Target); gerr == nil {
				for _, b := range baks {
					_ = os.Remove(b)
				}
			}
		case "delete":
			if dryRun {
				continue
			}
			if rerr := os.Remove(a.Target); rerr != nil && !os.IsNotExist(rerr) {
				a.Err = rerr
			}
		}
	}
	return plan, nil
}
