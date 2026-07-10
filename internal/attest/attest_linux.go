//go:build linux

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

package attest

import "context"

// Collect runs the Linux boot-state probes: Secure Boot (efivarfs read +
// optional mokutil downgrade-only corroboration) and TPM PCR readability.
// Read-only, local-only, no network.
func (p *Prober) Collect(ctx context.Context) []Result {
	return []Result{
		p.probeSecureBootLinux(ctx),
		p.probeTPM(ctx),
	}
}
