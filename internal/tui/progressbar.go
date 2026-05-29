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

package tui

import (
	"fmt"
)

// PlainBar returns a non-animated progress counter in the form "[N/M]".
// Used when animation is disabled (non-TTY, NO_COLOR, --json).
// When animation IS enabled the caller should drive a bubbles/progress model
// directly; this is the pure-text fallback.
func PlainBar(n, m int) string {
	return fmt.Sprintf("[%d/%d]", n, m)
}
