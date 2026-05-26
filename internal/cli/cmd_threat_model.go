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
	"github.com/spf13/cobra"
)

const threatModelText = `Abysslink Threat Model
======================

Defense                              Status
──────────────────────────────────── ──────────────────────────────
No public exposure (no Funnel)       ✓ enforced at schema level
Phone restricted: SSH+mosh only      ✓ ACL grants tcp/22, udp/60000-61000
SSH check re-auth every 12h          ✓ default checkPeriod (never extendable)
macOS sshd disabled w/ TS SSH        ✓ managed by ssh module
FileVault/LUKS required              ✓ doctor fails closed if off
API key in keychain                  ✓ secrets package (never on argv)
Audit trail                          ✓ every Apply writes audit.log
Reversible (backup+restore)          ✓ audit.Backup on every mutation
No SSH agent forwarding              ✓ enforced in generated ssh_config
No telemetry                         ✓ not implemented in v1
Tailnet Lock on by default           ✓ disablement secrets printed once only
ntfy binds tailnet IP only           ✓ never 0.0.0.0

Run 'abysslink doctor' to check the current status of each defense.
`

func newThreatModelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "threat-model",
		Short: "Print the security threat model and current mitigations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)
			printerInfo(p, threatModelText)
			return nil
		},
	}
}
