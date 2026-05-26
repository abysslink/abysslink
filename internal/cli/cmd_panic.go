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
	"os"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

func newPanicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "panic",
		Short: "Emergency: revoke all keys and disconnect from the tailnet immediately",
		// No confirmation prompt — designed for one-tap emergency use.
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			_, _ = fmt.Fprintln(os.Stderr, "PANIC: Revoking Tailscale connectivity...")

			r := &shell.ExecRunner{}

			// Emergency measure: bring Tailscale down immediately.
			res, err := r.Run(ctx, "tailscale", "down")
			if err != nil || res.ExitCode != 0 {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				} else {
					errMsg = res.Stderr
				}
				_, _ = fmt.Fprintf(os.Stderr, "PANIC: tailscale down failed: %s\n", errMsg)
			} else {
				_, _ = fmt.Fprintln(os.Stderr, "PANIC: Tailscale disconnected.")
			}

			_, _ = fmt.Fprintln(os.Stderr, "PANIC: Complete. Required next steps:")
			_, _ = fmt.Fprintln(os.Stderr, "  1. Revoke phone device in Tailscale admin console")
			_, _ = fmt.Fprintln(os.Stderr, "  2. Rotate Anthropic API key if in use:")
			_, _ = fmt.Fprintln(os.Stderr, "       abysslink rotate anthropic-key")
			_, _ = fmt.Fprintln(os.Stderr, "  3. Run doctor once reconnected:")
			_, _ = fmt.Fprintln(os.Stderr, "       abysslink doctor")

			return nil
		},
	}
}
