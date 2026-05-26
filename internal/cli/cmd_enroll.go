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

	"github.com/abysslink/abysslink/internal/qr"
	"github.com/spf13/cobra"
)

func newEnrollCmd() *cobra.Command {
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a device into the tailnet",
	}
	enroll.AddCommand(
		newEnrollPhoneCmd(),
		&cobra.Command{
			Use:   "rig",
			Short: "Add another laptop to the tailnet (v2 placeholder)",
			RunE: func(_ *cobra.Command, _ []string) error {
				return fmt.Errorf("enroll rig: multi-rig support is planned for v2")
			},
		},
	)
	return enroll
}

func newEnrollPhoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "phone",
		Short: "Mint auth key, display QR, and walk through phone pairing",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)

			printerInfo(p, "Phone enrollment — follow these steps:")
			printerInfo(p, "")
			printerInfo(p, "1. Install Tailscale on your phone:")
			printerInfo(p, "")

			// Print QR code pointing at Tailscale download.
			qr.PrintANSI(os.Stdout, "https://tailscale.com/download")

			printerInfo(p, "")
			printerInfo(p, "2. Sign in with your Tailscale account.")
			printerInfo(p, "")
			printerInfo(p, "3. In the Tailscale admin console, tag the phone device as 'tag:mobile'.")
			printerInfo(p, "   https://login.tailscale.com/admin/machines")
			printerInfo(p, "")
			printerInfo(p, "4. Run 'abysslink up --apply' to push the ACL granting phone access.")
			printerInfo(p, "")
			printerInfo(p, "5. Verify: abysslink doctor")

			return nil
		},
	}
}
