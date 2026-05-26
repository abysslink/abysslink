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
	"io"
	"os"
	"strings"

	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/spf13/cobra"
)

func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify [title] [body]",
		Short: "Send a notification via the ntfy backend or wrap a command",
	}

	cmd.Flags().Bool("stdin", false, "Read notification body from stdin")
	cmd.Flags().String("priority", "default", "Notification priority: low|default|high|urgent")
	cmd.Flags().String("tag", "", "User-supplied label")
	cmd.Flags().String("topic", "", "Routing key (default from config)")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		cc, err := loadCmdContext(c)
		if err != nil {
			return err
		}

		nm := notifymod.New(cc.runner, cc.cfg, nil)

		readStdin, _ := c.Flags().GetBool("stdin")

		if readStdin {
			body, readErr := io.ReadAll(os.Stdin)
			if readErr != nil {
				return fmt.Errorf("notify: read stdin: %w", readErr)
			}
			title := "notification"
			if len(args) > 0 {
				title = args[0]
			}
			return nm.Send(ctx, title, strings.TrimSpace(string(body)))
		}

		if len(args) >= 2 {
			return nm.Send(ctx, args[0], args[1])
		}
		if len(args) == 1 {
			return nm.Send(ctx, args[0], "")
		}

		return fmt.Errorf("notify: provide title and body, or use --stdin for body from stdin")
	}

	return cmd
}
