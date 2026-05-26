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

func newLockCmd() *cobra.Command {
	lock := &cobra.Command{
		Use:   "lock",
		Short: "Manage Tailnet Lock",
	}
	lock.AddCommand(
		&cobra.Command{Use: "init", Short: "Initialise Tailnet Lock and print disablement secrets", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "sign", Short: "Sign a node key with a Tailnet Lock signing key", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "status", Short: "Report Tailnet Lock status", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
		&cobra.Command{Use: "rotate", Short: "Rotate Tailnet Lock signing keys", RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("not implemented yet") }},
	)
	return lock
}
