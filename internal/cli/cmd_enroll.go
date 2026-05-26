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

func newEnrollCmd() *cobra.Command {
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a device into the tailnet",
	}
	enroll.AddCommand(
		&cobra.Command{
			Use:   "phone",
			Short: "Mint auth key, display QR, and walk through phone pairing",
			RunE: func(_ *cobra.Command, _ []string) error {
				// TODO(Phase 6): implement phone enrollment
				return fmt.Errorf("not implemented yet")
			},
		},
		&cobra.Command{
			Use:   "rig",
			Short: "Add another laptop to the tailnet (v2 placeholder)",
			RunE: func(_ *cobra.Command, _ []string) error {
				// TODO(Phase 6): implement rig enrollment
				return fmt.Errorf("not implemented yet")
			},
		},
	)
	return enroll
}
