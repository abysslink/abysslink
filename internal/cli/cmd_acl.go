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

func newACLCmd() *cobra.Command {
	acl := &cobra.Command{
		Use:   "acl",
		Short: "Manage Tailscale ACL policies",
	}
	acl.AddCommand(
		&cobra.Command{Use: "pull", Short: "Pull current ACL from the Tailscale admin API", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "push", Short: "Push local ACL changes to the Tailscale admin API", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "validate", Short: "Validate the local ACL against Tailscale rules", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "diff", Short: "Show diff between local and remote ACL", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
	)
	return acl
}
