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

package quorum

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// corpusEntry is one frozen red-team fixture. The corpus is CI law: every
// entry must yield DENY or ESCALATE, forever. Removing or weakening an entry
// is a security regression, not a test fix.
type corpusEntry struct {
	Label   string   `json:"label"`
	Argv    []string `json:"argv"`
	Expect  string   `json:"expect"` // "deny" | "not-allow"
	History []struct {
		Binary string   `json:"binary"`
		Args   []string `json:"args"`
		Repeat int      `json:"repeat"`
	} `json:"history,omitempty"`
}

// loadCorpus reads the frozen adversarial corpus.
func loadCorpus(t *testing.T) []corpusEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "adversarial", "corpus.json"))
	require.NoError(t, err, "the frozen adversarial corpus must be present")
	var entries []corpusEntry
	require.NoError(t, json.Unmarshal(raw, &entries))
	require.NotEmpty(t, entries)
	return entries
}

// runCorpusEntry evaluates one entry with a FRESH engine (per-entry history
// only) and returns the decision. {TMP} placeholders are substituted with a
// real temp file so V4's stat sweep has genuine world state.
func runCorpusEntry(t *testing.T, entry corpusEntry) Decision {
	t.Helper()
	e := New(Config{}, WithLogger(discardLogger()))
	for _, h := range entry.History {
		repeat := max(h.Repeat, 1)
		for range repeat {
			e.RecordExec(h.Binary, h.Args)
		}
	}
	argv := make([]string, len(entry.Argv))
	for i, a := range entry.Argv {
		if strings.Contains(a, "{TMP}") {
			a = strings.ReplaceAll(a, "{TMP}", tempTarget(t))
		}
		argv[i] = a
	}
	require.NotEmpty(t, argv)
	d, err := e.Evaluate(context.Background(), argv[0], argv[1:])
	require.NoError(t, err, "corpus entry %s", entry.Label)
	return d
}

// TestAdversarialCorpus: every frozen hostile input must DENY or ESCALATE —
// never ALLOW. This is the CI wrong-consensus battery.
func TestAdversarialCorpus(t *testing.T) {
	for _, entry := range loadCorpus(t) {
		t.Run(entry.Label, func(t *testing.T) {
			d := runCorpusEntry(t, entry)
			switch entry.Expect {
			case "deny":
				assert.Equal(t, OutcomeDeny, d.Outcome, "%s must DENY", entry.Label)
			case "not-allow":
				assert.NotEqual(t, OutcomeAllow, d.Outcome,
					"%s must never be ALLOWED (got %s)", entry.Label, d.Outcome)
			default:
				t.Fatalf("unknown expect %q in corpus entry %s", entry.Expect, entry.Label)
			}
		})
	}
}

// TestCorrelation_VerifiersDisagreeOnCorpus is the independence smoke (the
// Knight–Leveson lesson: independence is measured, not assumed). The four
// verifiers' verdict vectors across the corpus must not be pairwise
// identical — if two verifiers converge on identical judgments over the
// whole battery, their input signals have collapsed and the build fails.
func TestCorrelation_VerifiersDisagreeOnCorpus(t *testing.T) {
	vectors := map[string][]string{}
	names := []string{verifierSyntacticName, verifierPolicyName, verifierBehaviorName, verifierReversibilityName}

	for _, entry := range loadCorpus(t) {
		d := runCorpusEntry(t, entry)
		got := map[string]string{}
		for _, v := range d.Votes {
			got[v.Verifier] = fmt.Sprintf("%s@%s/%s", v.Verdict, v.Confidence, v.Err)
		}
		for _, n := range names {
			cell := got[n]
			if len(d.Votes) == 0 {
				cell = "floor-deny" // stage-0 fired; verifiers never voted
			}
			vectors[n] = append(vectors[n], cell)
		}
	}

	for i := range names {
		for j := i + 1; j < len(names); j++ {
			assert.NotEqual(t, vectors[names[i]], vectors[names[j]],
				"verifiers %q and %q produced IDENTICAL verdict vectors across the corpus — input-signal independence has collapsed",
				names[i], names[j])
		}
	}
}
