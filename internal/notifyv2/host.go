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

package notifyv2

import (
	"os"
	"strings"
)

// ShortHostname returns the local hostname with any domain stripped at the
// first dot; "" when the hostname cannot be resolved (or is a degenerate
// leading-dot name, which would fail Message.Host validation anyway). Both
// sides of the socket — the daemon's dispatcher enrichment and the CLI's
// Message construction — compose Message.Host through this single helper so
// the two can never disagree on the same machine.
func ShortHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	return h
}
