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

func newDaemonCmd() *cobra.Command {
	daemon := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the abysslinkd background daemon",
	}
	daemon.AddCommand(
		&cobra.Command{Use: "start", Short: "Start the daemon", RunE: func(cmd *cobra.Command, args []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "stop", Short: "Stop the daemon", RunE: func(cmd *cobra.Command, args []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "status", Short: "Show daemon status", RunE: func(cmd *cobra.Command, args []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "enable", Short: "Enable daemon auto-start on login", RunE: func(cmd *cobra.Command, args []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "disable", Short: "Disable daemon auto-start on login", RunE: func(cmd *cobra.Command, args []string) error { return fmt.Errorf("not implemented yet") }},
	)
	return daemon
}
