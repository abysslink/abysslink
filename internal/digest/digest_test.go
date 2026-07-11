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
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// day builds a UTC instant on the fixed test day 2026-07-09.
func day(hh, mm, ss int) time.Time {
	return time.Date(2026, 7, 9, hh, mm, ss, 0, time.UTC)
}

// targetDayWindow is the local-day window for 2026-07-09 in UTC (tests use UTC
// so the window and the stored UTC instants line up deterministically).
func targetDayWindow(t *testing.T) DayWindow {
	t.Helper()
	w, err := ParseWindow("2026-07-09", time.UTC)
	require.NoError(t, err)
	return w
}

func categoryCount(d Digest, slug Category) (CategorySummary, bool) {
	for _, c := range d.Categories {
		if c.Category == string(slug) {
			return c, true
		}
	}
	return CategorySummary{}, false
}

func TestCategorize_AllKnownOps(t *testing.T) {
	cases := map[string]Category{
		// exact table
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
		// panic:* prefix family (real + synthetic future action)
		"panic:destroy_local_api_key":     CategoryKillSwitch,
		"panic:destroy_rig_api_key":       CategoryKillSwitch,
		"panic:revoke_device_credentials": CategoryKillSwitch,
		"panic:revoke_device":             CategoryKillSwitch,
		"panic:tailscale_down":            CategoryKillSwitch,
		"panic:new_action":                CategoryKillSwitch,
		// arm-run:* prefix family (real + synthetic future phase)
		"arm-run:end": CategoryAction,
		"arm-run:foo": CategoryAction,
		// unknown => other
		"totally-new-op": CategoryOther,
		"":               CategoryOther,
	}
	for op, want := range cases {
		assert.Equalf(t, want, categorize(op), "categorize(%q)", op)
	}
}

func TestCompute_MultiCategoryCounts(t *testing.T) {
	w := targetDayWindow(t)
	entries := []audit.Entry{
		{Op: "wol", Target: "rig-1/aa:bb:cc:dd:ee:ff", Time: day(9, 0, 0)},           // action applied
		{Op: "arm-run:end", Target: "/state/casts/a.cast", Time: day(9, 16, 0)},      // action applied
		{Op: "approve-decision", Target: "request:abc123", Time: day(10, 0, 0)},      // approval applied
		{Op: "ack-receipt", Target: "device:phone-1", Time: day(10, 5, 0)},           // waited applied
		{Op: "deadman-lockdown", Target: "no operator contact", Time: day(14, 0, 0)}, // deadman applied
		{Op: "panic:tailscale_down", Target: "panic", Time: day(14, 5, 0)},           // kill-switch applied
		{Op: "write", Target: "/cfg/a.yaml", Time: day(8, 0, 0), DryRun: true},       // config dry-run
		{Op: "write", Target: "/cfg/b.yaml", Time: day(8, 1, 0), DryRun: true},       // config dry-run
		{Op: "write", Target: "/cfg/c.yaml", Time: day(8, 2, 0)},                     // config applied
		{Op: "backup", Target: "/cfg/a.yaml.bak", Time: day(8, 3, 0)},                // backup applied
	}
	d := Compute(entries, w)

	assert.Equal(t, "2026-07-09", d.Date)
	assert.Equal(t, 10, d.TotalEntries)
	assert.Equal(t, 8, d.Applied)
	assert.Equal(t, 2, d.DryRun)
	// invariant 1: applied + dry-run == total
	assert.Equal(t, d.TotalEntries, d.Applied+d.DryRun)

	// invariant 2: sum(category.count) == total
	sum := 0
	for _, c := range d.Categories {
		sum += c.Count
	}
	assert.Equal(t, d.TotalEntries, sum)

	// spot-check per-category rows
	action, ok := categoryCount(d, CategoryAction)
	require.True(t, ok)
	assert.Equal(t, 2, action.Count)
	assert.Equal(t, 2, action.Applied)
	assert.Equal(t, 0, action.DryRun)

	cfg, ok := categoryCount(d, CategoryConfigMutation)
	require.True(t, ok)
	assert.Equal(t, 3, cfg.Count)
	assert.Equal(t, 1, cfg.Applied)
	assert.Equal(t, 2, cfg.DryRun)

	backup, ok := categoryCount(d, CategoryBackup)
	require.True(t, ok)
	assert.Equal(t, 1, backup.Count)

	// human_gate_events = approval + agent-waited-on-human
	assert.Equal(t, 2, d.HumanGateEvents)

	// at least 6 categories present with data
	nonZero := 0
	for _, c := range d.Categories {
		if c.Count > 0 {
			nonZero++
		}
	}
	assert.GreaterOrEqual(t, nonZero, 6)

	// the 8 known categories are always present (zeros included), no "other"
	assert.Len(t, d.Categories, 8)
	_, hasOther := categoryCount(d, CategoryOther)
	assert.False(t, hasOther)
}

func TestCompute_OtherAppendedOnlyWhenPresent(t *testing.T) {
	w := targetDayWindow(t)
	d := Compute([]audit.Entry{
		{Op: "some-future-op", Target: "/x", Time: day(9, 0, 0)},
	}, w)
	other, ok := categoryCount(d, CategoryOther)
	require.True(t, ok, "other must be emitted when an unrecognized op is present")
	assert.Equal(t, 1, other.Count)
	// other is appended last, after the 8 known.
	assert.Equal(t, string(CategoryOther), d.Categories[len(d.Categories)-1].Category)
	// unknown op is a signal category → appears in notable.
	require.Len(t, d.Notable, 1)
	assert.Equal(t, "some-future-op", d.Notable[0].Op)
}

func TestCompute_WindowFilter(t *testing.T) {
	w := targetDayWindow(t)
	entries := []audit.Entry{
		{Op: "wol", Target: "a", Time: time.Date(2026, 7, 8, 23, 59, 59, 0, time.UTC)}, // day before
		{Op: "wol", Target: "b", Time: time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC)},    // Start (inclusive)
		{Op: "wol", Target: "c", Time: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)},   // in-window
		{Op: "wol", Target: "d", Time: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)},   // End (exclusive)
		{Op: "wol", Target: "e", Time: time.Date(2026, 7, 10, 0, 0, 1, 0, time.UTC)},   // day after
	}
	d := Compute(entries, w)
	// Only Start (inclusive) and the mid-day entry fall in [Start, End).
	assert.Equal(t, 2, d.TotalEntries)
	action, ok := categoryCount(d, CategoryAction)
	require.True(t, ok)
	assert.Equal(t, 2, action.Count)
}

func TestCompute_WindowFilter_LocalDayFromUTC(t *testing.T) {
	// A fixed-offset location (UTC+5): a UTC instant at 20:00 on the previous UTC
	// day is 01:00 local on the target day and must be counted.
	loc := time.FixedZone("UTC+5", 5*3600)
	w, err := ParseWindow("2026-07-09", loc)
	require.NoError(t, err)
	// 2026-07-08T20:00:00Z == 2026-07-09T01:00:00+05:00 (local day 07-09).
	entries := []audit.Entry{
		{Op: "wol", Target: "utc-stored", Time: time.Date(2026, 7, 8, 20, 0, 0, 0, time.UTC)},
	}
	d := Compute(entries, w)
	assert.Equal(t, 1, d.TotalEntries, "a UTC-stored instant on the target LOCAL day must be counted")
}

func TestCompute_EmptyDay(t *testing.T) {
	w := targetDayWindow(t)

	// zero entries
	d := Compute(nil, w)
	assert.Equal(t, 0, d.TotalEntries)
	assert.Equal(t, 0, d.Applied)
	assert.Equal(t, 0, d.DryRun)
	assert.Equal(t, 0, d.HumanGateEvents)
	assert.Len(t, d.Categories, 8, "all known categories present even on an empty day")
	for _, c := range d.Categories {
		assert.Equal(t, 0, c.Count)
	}
	// non-nil empty slices (marshal as [] not null)
	require.NotNil(t, d.Notable)
	require.NotNil(t, d.Casts)
	assert.Empty(t, d.Notable)
	assert.Empty(t, d.Casts)

	// entries that all fall outside the window behave the same
	d2 := Compute([]audit.Entry{
		{Op: "wol", Target: "a", Time: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)},
	}, w)
	assert.Equal(t, 0, d2.TotalEntries)
	require.NotNil(t, d2.Notable)
	require.NotNil(t, d2.Casts)
}

func TestCompute_NotableExcludesRoutine(t *testing.T) {
	w := targetDayWindow(t)
	entries := []audit.Entry{
		{Op: "write", Target: "/cfg/a.yaml", Time: day(8, 0, 0)},
		{Op: "backup", Target: "/cfg/a.yaml.bak", Time: day(8, 1, 0)},
		{Op: "sec-fix", Target: "chmod:/cfg/a.yaml", Time: day(8, 2, 0)},
		{Op: "delete", Target: "/cfg/old.yaml", Time: day(8, 3, 0)},
		{Op: "restore", Target: "/cfg/a.yaml", Time: day(8, 4, 0)},
		{Op: "deadman-lockdown", Target: "no operator contact", Time: day(14, 0, 0)},
		{Op: "panic:tailscale_down", Target: "panic", Time: day(14, 1, 0)},
		{Op: "approve-decision", Target: "request:abc", Time: day(10, 0, 0)},
		{Op: "wol", Target: "rig/aa:bb", Time: day(9, 0, 0)},
		{Op: "arm-run:end", Target: "/casts/x.cast", Time: day(9, 16, 0)},
	}
	d := Compute(entries, w)

	notableOps := map[string]bool{}
	for _, n := range d.Notable {
		notableOps[n.Op] = true
	}
	// routine ops (config-mutation, backup categories) are excluded
	for _, routine := range []string{"write", "backup", "sec-fix", "delete", "restore"} {
		assert.Falsef(t, notableOps[routine], "%s must NOT be in notable (routine category)", routine)
	}
	// signal ops are present
	for _, signal := range []string{"deadman-lockdown", "panic:tailscale_down", "approve-decision", "wol", "arm-run:end"} {
		assert.Truef(t, notableOps[signal], "%s must be in notable (signal category)", signal)
	}
}

func TestCompute_NotableOrderAndCap(t *testing.T) {
	w := targetDayWindow(t)
	// 205 signal (wol) events, seeded out of order by second so the stable sort
	// is exercised; the cap keeps the first 200 chronologically.
	var entries []audit.Entry
	for i := 0; i < 205; i++ {
		entries = append(entries, audit.Entry{
			Op:     "wol",
			Target: "rig/x",
			Time:   time.Date(2026, 7, 9, 0, 0, i, 0, time.UTC),
		})
	}
	// shuffle deterministically: reverse
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	d := Compute(entries, w)
	assert.Len(t, d.Notable, maxNotable)
	assert.Equal(t, 5, d.NotableOmitted)
	// notable is time-ascending
	assert.True(t, sort.SliceIsSorted(d.Notable, func(i, j int) bool {
		return d.Notable[i].Time.Before(d.Notable[j].Time)
	}))
	// first kept event is the earliest (00:00:00), not a shuffled one
	assert.Equal(t, day(0, 0, 0), d.Notable[0].Time)
}

func TestCompute_Casts(t *testing.T) {
	w := targetDayWindow(t)
	entries := []audit.Entry{
		{Op: "arm-run:end", Target: "/casts/z.cast", Time: day(9, 0, 0)},
		{Op: "arm-run:end", Target: "/casts/a.cast", Time: day(9, 30, 0)},
		{Op: "arm-run:end", Target: "/casts/a.cast", Time: day(10, 0, 0)},        // duplicate path
		{Op: "wol", Target: "/casts/not-a-cast", Time: day(11, 0, 0)},            // must NOT contribute
		{Op: "arm-run:start", Target: "/casts/ignored.cast", Time: day(8, 0, 0)}, // only :end contributes
	}
	d := Compute(entries, w)
	assert.Equal(t, []string{"/casts/a.cast", "/casts/z.cast"}, d.Casts, "sorted + deduped, only arm-run:end")
}

func TestSafeTarget(t *testing.T) {
	// pass-through cases (real audit Targets)
	passthrough := []string{
		"/home/u/.local/state/abysslink/casts/run.cast",
		"rig-1/aa:bb:cc:dd:ee:ff",
		"aa:bb:cc:dd:ee:ff",
		"request:abc123",
		"device:phone-1",
		"epoch:2",
		"chmod:/etc/abysslink/config",
		"panic",
		"no operator contact for 24h0m0s",
	}
	for _, tgt := range passthrough {
		assert.Equalf(t, tgt, safeTarget("op", tgt), "expected %q to pass through unchanged", tgt)
	}

	// every configured credential prefix redacts a separator-free token. Tokens
	// are constructed at runtime so no key-shaped literal appears in source.
	for _, kp := range secretKeyPrefixes {
		tok := kp + "x1y2z3q4w5"
		assert.Equalf(t, redactedTarget, safeTarget("op", tok), "prefix %q must redact", kp)
	}

	// a long, separator-free, high-entropy blob (>=40 runes) => redacted.
	assert.Equal(t, redactedTarget, safeTarget("op", strings.Repeat("a1b2c3d4e5", 5))) // 50 runes

	// over-long spaced reason => truncated to 200 runes + ellipsis (NOT redacted)
	long := strings.Repeat("word ", 60) // 300 runes, contains spaces
	got := safeTarget("op", long)
	assert.NotEqual(t, redactedTarget, got)
	assert.True(t, strings.HasSuffix(got, "…"))
	assert.Equal(t, maxTargetRunes+1, len([]rune(got))) // 200 + the ellipsis rune
}

func TestDigest_JSONByteStable(t *testing.T) {
	w := targetDayWindow(t)
	entries := []audit.Entry{
		{Op: "wol", Target: "rig/aa:bb", Time: day(9, 0, 0)},
		{Op: "approve-decision", Target: "request:x", Time: day(10, 0, 0)},
		{Op: "write", Target: "/cfg/a.yaml", Time: day(8, 0, 0), DryRun: true},
		{Op: "arm-run:end", Target: "/casts/a.cast", Time: day(9, 16, 0)},
	}
	d := Compute(entries, w)

	b1, err := json.Marshal(d)
	require.NoError(t, err)
	b2, err := json.Marshal(d)
	require.NoError(t, err)
	assert.Equal(t, string(b1), string(b2), "marshalling the same Digest twice must be byte-identical")

	// re-computing from the same input is also byte-stable
	b3, err := json.Marshal(Compute(entries, w))
	require.NoError(t, err)
	assert.Equal(t, string(b1), string(b3))

	// categories are slug-sorted (the 8 known set has no "other" here)
	slugs := make([]string, 0, len(d.Categories))
	for _, c := range d.Categories {
		slugs = append(slugs, c.Category)
	}
	assert.True(t, sort.StringsAreSorted(slugs), "categories must be slug-sorted: %v", slugs)

	// no null slices in the serialized form
	s := string(b1)
	assert.NotContains(t, s, "\"notable\":null")
	assert.NotContains(t, s, "\"casts\":null")
	assert.NotContains(t, s, "\"categories\":null")
}

func TestTodayWindow(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 30, 45, 0, time.UTC)
	w := TodayWindow(now)
	assert.Equal(t, "2026-07-09", w.Date)
	assert.Equal(t, time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC), w.Start)
	assert.Equal(t, time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC), w.End)
}

func TestParseWindow_Invalid(t *testing.T) {
	_, err := ParseWindow("2026-13-40", time.UTC)
	assert.Error(t, err)
	_, err = ParseWindow("not-a-date", time.UTC)
	assert.Error(t, err)
	_, err = ParseWindow("2026-07-09", nil) // nil loc defaults to Local
	assert.NoError(t, err)
}
