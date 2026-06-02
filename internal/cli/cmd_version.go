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
)

// provenanceJSON is the --provenance --json record for `abysslink version`.
type provenanceJSON struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	SLSAURL   string `json:"slsa_url"`
	BundleURL string `json:"bundle_url"`
}

func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Example: `  # Show abysslink version, commit, and build date
  abysslink version

  # Include supply-chain provenance (SLSA + cosign bundle URLs)
  abysslink version --provenance`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			provenance, _ := cmd.Flags().GetBool("provenance")
			jsonOut, _ := cmd.Flags().GetBool("json")
			p := newPrinter(cmd)

			if jsonOut {
				p.PrintJSON(provenanceJSON{
					Version:   version,
					Commit:    commit,
					BuildDate: buildDate,
					SLSAURL:   slsaURL,
					BundleURL: bundleURL,
				})
				return nil
			}

			printerInfo(p, fmt.Sprintf("abysslink %s (%s) built %s", version, commit, buildDate))
			if provenance {
				printerInfo(p, "SLSA provenance: "+orNone(slsaURL))
				printerInfo(p, "Bundle: "+orNone(bundleURL))
			}
			return nil
		},
	}
	cmd.Flags().Bool("provenance", false, "show SLSA provenance and cosign bundle URLs")
	cmd.Flags().Bool("json", false, "emit version/provenance info as JSON")
	return cmd
}

// orNone returns s, or a "(none — dev build)" placeholder when s is empty.
func orNone(s string) string {
	if s == "" {
		return "(none — dev build)"
	}
	return s
}
