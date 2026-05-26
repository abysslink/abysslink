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

func newBackupCmd() *cobra.Command {
	backup := &cobra.Command{
		Use:   "backup",
		Short: "Manage configuration backups",
	}
	backup.AddCommand(
		&cobra.Command{Use: "ls", Short: "List available backups", RunE: func(cmd *cobra.Command, args []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "restore", Short: "Restore a configuration backup", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return fmt.Errorf("not implemented yet") }},
	)
	return backup
}
