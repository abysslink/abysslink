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
	"bytes"
	"context"
	"fmt"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/spf13/cobra"
)

// newNetBirdEventsCmd returns the "netbird events" command. Without --follow it
// prints the current snapshot of audit events and exits. With --follow it polls
// GET /api/events/audit with bounded backoff, printing only newly-appended
// events (watermark-deduplicated), until the context is cancelled (Ctrl+C).
func newNetBirdEventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Tail NetBird audit events (use --follow to stream)",
		Example: `  abysslink netbird events
  abysslink netbird events --follow
  abysslink --json netbird events`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			follow, _ := cmd.Flags().GetBool("follow")
			return netbirdEventsRunE(cmd.Context(), cc, newPrinter(cmd), follow)
		},
	}
	cmd.Flags().Bool("follow", false, "continuously poll and print new events until interrupted")
	return cmd
}

// netbirdEventsRunE tails audit events to the printer. Each event is emitted as
// a JSON line via the backend TailEvents writer; the printerLineWriter routes
// those lines through the Printer so --json and human output both stay on the
// Printer abstraction (no direct stdout writes). Context cancellation exits
// cleanly with a nil error.
func netbirdEventsRunE(ctx context.Context, cc *cmdContext, p Printer, follow bool) error {
	w := &printerLineWriter{p: p}
	if err := backend.NetBirdTailEvents(ctx, cc.cfg, w, follow); err != nil {
		return fmt.Errorf("netbird events: %w", err)
	}
	w.flush()
	return nil
}

// printerLineWriter is an io.Writer that buffers bytes and emits each complete
// newline-terminated line through the Printer. The backend writes one JSON
// object per line; this adapter keeps event output on the Printer abstraction
// (CLAUDE.md: only the Printer may write to stdout/stderr).
type printerLineWriter struct {
	p   Printer
	buf bytes.Buffer
}

func (w *printerLineWriter) Write(b []byte) (int, error) {
	n := len(b)
	w.buf.Write(b)
	for {
		idx := bytes.IndexByte(w.buf.Bytes(), '\n')
		if idx < 0 {
			break
		}
		line := string(w.buf.Next(idx + 1))
		// Trim the trailing newline; Printer.Print re-adds one (human) or wraps (JSON).
		w.p.Print(line[:len(line)-1])
	}
	return n, nil
}

// flush emits any trailing partial line that was not newline-terminated.
func (w *printerLineWriter) flush() {
	if w.buf.Len() > 0 {
		w.p.Print(w.buf.String())
		w.buf.Reset()
	}
}
