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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/abysslink/abysslink/internal/gate"
	"github.com/abysslink/abysslink/internal/quorum"
)

func newQuorumCmd() *cobra.Command {
	q := &cobra.Command{
		Use:   "quorum",
		Short: "Inspect the quorum-sensing action gate",
	}
	q.AddCommand(newQuorumEvalCmd())
	return q
}

// newQuorumEvalCmd is the rule-authoring/debug UX: a READ-ONLY shadow
// evaluation of one command line through the stage-0 floor and the four-
// verifier lattice. It prints the full vote vector (dissent first) and NEVER
// executes the command. No audit entry is written — this is a what-if query,
// not a decision on a real exec.
func newQuorumEvalCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "eval -- <cmd> [args...]",
		Short: "Shadow-evaluate a command through the quorum lattice (never executes)",
		Example: `  # What would the quorum decide for a force-push to main?
  abysslink quorum eval -- git push --force origin main

  # Probe the immutable deny-floor
  abysslink quorum eval -- tailscale funnel 2586`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			commandHeader(p, "quorum eval", styleMuted.Render("read-only — the command is never executed"))

			if !cc.cfg.Quorum.Enabled {
				printerInfo(p, styleWarn.Render("note: quorum.enabled=false in config — this is a what-if evaluation only"))
			}

			// Shadow-labeled engine; no audit appender (read-only debug); the
			// observe-only CLI runner serves V4's read-only VCS probes.
			engine := quorum.New(cc.cfg.Quorum.EngineConfig(false),
				quorum.WithRunner(cc.runner),
				quorum.WithClosureHashFunc(gate.ClosureHashOf),
			)
			d, err := engine.Evaluate(ctx, args[0], args[1:])
			if err != nil {
				return fmt.Errorf("quorum eval: %w", err)
			}
			printQuorumDecision(p, d)
			return nil
		},
	}
}

// printQuorumDecision renders one decision via the Printer: outcome, tier,
// floor rule, matched codes, and the dissent-first vote vector.
func printQuorumDecision(p Printer, d quorum.Decision) {
	switch d.Outcome {
	case quorum.OutcomeDeny:
		printerInfo(p, "  outcome: "+styleFatal.Render("DENY — no approval path"))
	case quorum.OutcomeEscalate:
		printerInfo(p, "  outcome: "+styleWarn.Render(fmt.Sprintf("ESCALATE (tier %d)", int(d.Tier))))
	default:
		printerInfo(p, "  outcome: "+styleSuccess.Render("ALLOW (audit-only)"))
	}
	printerInfo(p, "  binary:  "+d.Binary+"   closure: "+d.Closure8)
	if d.FloorRule != "" {
		printerInfo(p, "  floor:   "+styleFatal.Render(d.FloorRule)+" (compiled deny-floor — un-askable)")
	}
	if len(d.Matched) > 0 {
		printerInfo(p, "  matched: "+fmt.Sprintf("%v", d.Matched))
	}
	if summary := d.VoteSummary(); summary != "" {
		printerInfo(p, "  votes (dissent first):")
		printerInfo(p, "    "+summary)
	}
}
