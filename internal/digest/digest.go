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

package digest

import (
	"sort"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
)

// Category is a stable, operator-meaningful bucket that an audit op maps to.
// Each op maps to exactly one Category so counts never double-count.
type Category string

const (
	// CategoryAction — agent/action runs: arm-run:* (KILL-05) and wol.
	CategoryAction Category = "action-run"
	// CategoryApproval — a human RESOLVED an approval request (approve OR deny;
	// the verdict lives in the receipt body, not the audit op).
	CategoryApproval Category = "approval"
	// CategoryWaitedOnHuman — an agent action was gated on / acknowledged by a
	// human (ack-receipt).
	CategoryWaitedOnHuman Category = "agent-waited-on-human"
	// CategoryKillSwitch — emergency kill-switch actions: panic:*.
	CategoryKillSwitch Category = "kill-switch"
	// CategoryDeadman — the dead-man's switch fired (deadman-lockdown).
	CategoryDeadman Category = "deadman"
	// CategoryRotation — audit HMAC signing-key rotation (rotate-audit-hmac).
	CategoryRotation Category = "rotation"
	// CategoryConfigMutation — file mutations: write, delete, sec-fix.
	CategoryConfigMutation Category = "config-mutation"
	// CategoryBackup — backup / restore: backup, restore, restore-unverified.
	CategoryBackup Category = "backup"
	// CategoryOther — catch-all for ops this binary does not recognize (a future
	// release added an op this diary predates). Emitted only when its count > 0
	// so a normal day never shows it; surfacing it keeps totals reconciled.
	CategoryOther Category = "other"
)

const (
	// maxNotable caps the notable list (defensive; signal categories are
	// inherently low-volume so this rarely bites). When capped, the first
	// maxNotable chronological events are kept and NotableOmitted records the rest.
	maxNotable = 200
	// opArmRunEnd is the ONLY op whose Target is an asciinema cast path (KILL-05).
	// There is no recording index anywhere in the codebase — casts are surfaced
	// exclusively from this op's Target.
	opArmRunEnd = "arm-run:end"
	// dateLayout is the local calendar-day layout used for --date and Date labels.
	dateLayout = "2006-01-02"
	// redactedTarget replaces a secret-shaped Target (defense-in-depth; never
	// fires on real path/id data).
	redactedTarget = "<redacted:secret-shaped-target>"
	// maxTargetRunes bounds a rendered Target so a pathological reason string
	// cannot blow up the digest.
	maxTargetRunes = 200
)

// opCategory is the exact op→category table (every op EXCEPT the two prefix
// families panic:* and arm-run:*, which categorize handles by prefix).
var opCategory = map[string]Category{
	"wol":                CategoryAction,
	"approve-decision":   CategoryApproval,
	"ack-receipt":        CategoryWaitedOnHuman,
	"deadman-lockdown":   CategoryDeadman,
	"rotate-audit-hmac":  CategoryRotation,
	"write":              CategoryConfigMutation,
	"delete":             CategoryConfigMutation,
	"sec-fix":            CategoryConfigMutation,
	"backup":             CategoryBackup,
	"restore":            CategoryBackup,
	"restore-unverified": CategoryBackup,
}

// knownCategoriesSorted is the fixed set of known categories in slug-sorted
// order. Compute always emits all of them (zeros included) so the JSON shape is
// stable regardless of the data; CategoryOther is appended only when present.
var knownCategoriesSorted = []Category{
	CategoryAction,         // action-run
	CategoryWaitedOnHuman,  // agent-waited-on-human
	CategoryApproval,       // approval
	CategoryBackup,         // backup
	CategoryConfigMutation, // config-mutation
	CategoryDeadman,        // deadman
	CategoryKillSwitch,     // kill-switch
	CategoryRotation,       // rotation
}

// knownTargetPrefixes are the id/label prefixes real audit Targets use. A Target
// carrying one is structurally an id (never a secret) and passes safeTarget
// untouched.
var knownTargetPrefixes = []string{"request:", "device:", "epoch:", "chmod:"}

// secretKeyPrefixes are well-known credential prefixes. A separator-free,
// prefix-free Target starting with one is treated as secret-shaped and redacted.
var secretKeyPrefixes = []string{"sk-", "akia", "ghp_", "xox"}

// Digest is the deterministic, secret-free summary of one local calendar day of
// the audit chain. It is the exact object emitted by `abysslink --json diary`.
type Digest struct {
	Date            string            `json:"date"`              // "YYYY-MM-DD" (local day summarized)
	TotalEntries    int               `json:"total_entries"`     //
	Applied         int               `json:"applied"`           // DryRun == false
	DryRun          int               `json:"dry_run"`           // DryRun == true
	HumanGateEvents int               `json:"human_gate_events"` // derived: approval + agent-waited-on-human
	Categories      []CategorySummary `json:"categories"`        // fixed 8 slug-sorted + optional "other"
	Notable         []NotableEvent    `json:"notable"`           // signal events, time-ordered, capped; non-nil
	NotableOmitted  int               `json:"notable_omitted"`   // >0 iff Notable was capped
	Casts           []string          `json:"casts"`             // arm-run:end Targets, sorted+deduped; non-nil
}

// CategorySummary is the per-category count row.
type CategorySummary struct {
	Category string `json:"category"` // stable slug
	Count    int    `json:"count"`
	Applied  int    `json:"applied"`
	DryRun   int    `json:"dry_run"`
}

// NotableEvent is a PROJECTED view of an audit.Entry — deliberately NOT the raw
// entry. It carries only path/id + time + classification and structurally CANNOT
// emit Hash/Sig/PrevHash/KeyEpoch (the chain digests), so the diary can never
// leak one even if a future op mis-populated those fields.
type NotableEvent struct {
	Time     time.Time `json:"time"`
	Op       string    `json:"op"`
	Target   string    `json:"target"` // path/id, run through safeTarget
	Category string    `json:"category"`
	DryRun   bool      `json:"dry_run"`
}

// DayWindow is one local calendar day expressed as an absolute [Start,End)
// instant range. Entries are stored in UTC, but time comparison is absolute so a
// window computed from a local location selects the correct calendar day.
type DayWindow struct {
	Date  string    // "YYYY-MM-DD" label (local calendar day)
	Start time.Time // inclusive
	End   time.Time // exclusive (Start + one calendar day via AddDate, DST-safe)
}

// TodayWindow returns the DayWindow for the local calendar day containing now.
// The clock is read exactly once, at the command layer, and passed in — Compute
// never calls time.Now.
func TodayWindow(now time.Time) DayWindow {
	y, m, d := now.Date()
	start := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	return DayWindow{
		Date:  start.Format(dateLayout),
		Start: start,
		End:   start.AddDate(0, 0, 1),
	}
}

// ParseWindow builds the DayWindow for the "YYYY-MM-DD" date interpreted in loc
// (the command layer passes time.Local). A malformed date returns the parse
// error unwrapped so the caller can wrap it with a command-scoped message.
func ParseWindow(date string, loc *time.Location) (DayWindow, error) {
	if loc == nil {
		loc = time.Local
	}
	start, err := time.ParseInLocation(dateLayout, date, loc)
	if err != nil {
		return DayWindow{}, err
	}
	return DayWindow{
		Date:  start.Format(dateLayout),
		Start: start,
		End:   start.AddDate(0, 0, 1),
	}, nil
}

// Compute filters entries to the window w, classifies each into exactly one
// category, and returns a deterministic Digest. It is pure: no clock, no map
// iteration in the output, no I/O.
func Compute(entries []audit.Entry, w DayWindow) Digest {
	d := Digest{Date: w.Date}
	counts := newCounters()
	signal := []NotableEvent{} // non-nil so an empty day marshals as [] not null
	castSet := make(map[string]struct{})

	for i := range entries {
		e := entries[i]
		if !inWindow(e.Time, w) {
			continue
		}
		cat := categorize(e.Op)
		counts.add(cat, e.DryRun)
		d.TotalEntries++
		if e.DryRun {
			d.DryRun++
		} else {
			d.Applied++
		}
		if cat == CategoryApproval || cat == CategoryWaitedOnHuman {
			d.HumanGateEvents++
		}
		if e.Op == opArmRunEnd && e.Target != "" {
			// Bound/redact the cast target the same way notable events do, so a
			// pathological cast path cannot bloat the object or diverge in length
			// from its notable-view twin (cast paths never trip the redaction
			// branch since they contain '/', but the length bound still applies).
			castSet[safeTarget(e.Op, e.Target)] = struct{}{}
		}
		if !isRoutineCategory(cat) {
			signal = append(signal, NotableEvent{
				Time:     e.Time,
				Op:       e.Op,
				Target:   safeTarget(e.Op, e.Target),
				Category: string(cat),
				DryRun:   e.DryRun,
			})
		}
	}

	d.Categories = counts.summaries()
	d.Notable, d.NotableOmitted = finalizeNotable(signal)
	d.Casts = sortedKeys(castSet)
	return d
}

// inWindow reports whether the absolute instant t falls in [w.Start, w.End).
func inWindow(t time.Time, w DayWindow) bool {
	return !t.Before(w.Start) && t.Before(w.End)
}

// categorize maps an op to its single Category (deterministic, no map in the hot
// path except the exact-match lookup): exact opCategory match, then the panic:*
// and arm-run:* prefix families, else CategoryOther.
func categorize(op string) Category {
	if c, ok := opCategory[op]; ok {
		return c
	}
	if strings.HasPrefix(op, "panic:") {
		return CategoryKillSwitch
	}
	if strings.HasPrefix(op, "arm-run:") {
		return CategoryAction
	}
	return CategoryOther
}

// isRoutineCategory reports whether a category is high-volume routine noise
// (config-mutation, backup) that is represented by counts only and excluded from
// the notable list. Per-file detail lives in `abysslink logs`.
func isRoutineCategory(c Category) bool {
	return c == CategoryConfigMutation || c == CategoryBackup
}

// safeTarget is the secret-safety guardrail for the one free-text audit field.
// Real Targets (paths with "/", MACs, prefixed ids, "panic", spaced reasons)
// pass through unchanged. A secret-shaped Target is redacted wholesale; an
// over-long Target is truncated to maxTargetRunes with an ellipsis. The first
// argument (the op) is accepted for symmetry with the audit vocabulary but
// classification is driven entirely by the Target's own shape.
func safeTarget(_, target string) string {
	if isSecretShaped(target) {
		return redactedTarget
	}
	r := []rune(target)
	if len(r) > maxTargetRunes {
		return string(r[:maxTargetRunes]) + "…"
	}
	return target
}

// isSecretShaped reports whether target looks like a credential rather than a
// path/id/reason. Any Target with a path separator, a space, the "panic"
// sentinel, or a known id prefix is structurally safe and returns false. A
// remaining separator-free token is secret-shaped when it begins with a known
// key prefix or is a long (>=40-rune) unbroken blob. This never fires on real
// audit data (all real Targets are paths/ids/prefixed/spaced) — it is
// defense-in-depth against a mis-authored future op.
func isSecretShaped(target string) bool {
	if target == "" {
		return false
	}
	if strings.ContainsAny(target, "/ ") {
		return false
	}
	if target == "panic" {
		return false
	}
	for _, p := range knownTargetPrefixes {
		if strings.HasPrefix(target, p) {
			return false
		}
	}
	lower := strings.ToLower(target)
	for _, kp := range secretKeyPrefixes {
		if strings.HasPrefix(lower, kp) {
			return true
		}
	}
	return len([]rune(target)) >= 40
}

// catAcc accumulates per-category counts.
type catAcc struct{ count, applied, dryRun int }

// counters accumulates category counts keyed by Category. Output order is never
// derived from map iteration — summaries() materializes via the fixed sorted
// slice.
type counters struct{ m map[Category]*catAcc }

// newCounters pre-seeds every known category so zero rows are always emitted.
func newCounters() *counters {
	m := make(map[Category]*catAcc, len(knownCategoriesSorted)+1)
	for _, c := range knownCategoriesSorted {
		m[c] = &catAcc{}
	}
	return &counters{m: m}
}

func (c *counters) add(cat Category, dryRun bool) {
	a := c.m[cat]
	if a == nil {
		a = &catAcc{}
		c.m[cat] = a
	}
	a.count++
	if dryRun {
		a.dryRun++
	} else {
		a.applied++
	}
}

// summaries materializes the category rows: the fixed 8 known slugs in
// slug-sorted order (zeros included), with "other" appended only when present.
func (c *counters) summaries() []CategorySummary {
	out := make([]CategorySummary, 0, len(knownCategoriesSorted)+1)
	for _, cat := range knownCategoriesSorted {
		a := c.m[cat]
		out = append(out, CategorySummary{
			Category: string(cat),
			Count:    a.count,
			Applied:  a.applied,
			DryRun:   a.dryRun,
		})
	}
	if o := c.m[CategoryOther]; o != nil && o.count > 0 {
		out = append(out, CategorySummary{
			Category: string(CategoryOther),
			Count:    o.count,
			Applied:  o.applied,
			DryRun:   o.dryRun,
		})
	}
	return out
}

// finalizeNotable stable-sorts the signal events by Time (equal times keep
// append/causal order) and caps at maxNotable, returning the kept slice
// (always non-nil) and the omitted count.
func finalizeNotable(signal []NotableEvent) ([]NotableEvent, int) {
	sort.SliceStable(signal, func(i, j int) bool {
		return signal[i].Time.Before(signal[j].Time)
	})
	omitted := 0
	if len(signal) > maxNotable {
		omitted = len(signal) - maxNotable
		signal = signal[:maxNotable]
	}
	if signal == nil {
		signal = []NotableEvent{}
	}
	return signal, omitted
}

// sortedKeys returns the map keys sorted; the result is always non-nil so Casts
// marshals as [] on an empty day, never null.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
