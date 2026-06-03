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

package backend

import (
	"fmt"
	"io"
)

// maxBackendBody is the maximum REST response body size accepted from any
// self-hosted backend (Headscale, NetBird). Chosen well above the largest
// legit response (~2 MB for a 1000-node fleet list) while preventing
// memory-exhaustion DoS from hostile/compromised controllers (A11 / DOS-01).
const maxBackendBody int64 = 8 * 1024 * 1024 // 8 MiB

// readLimited reads at most n bytes from r. If the body exceeds n bytes it
// returns an explicit error — io.LimitReader alone silently truncates; the
// N+1 sentinel detects overflow before JSON decode (D-06).
func readLimited(r io.ReadCloser, n int64) ([]byte, error) {
	limited := io.LimitReader(r, n+1) // N+1 sentinel: reads one extra byte to detect overflow
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > n {
		return nil, fmt.Errorf("response body exceeded %d bytes", n)
	}
	return data, nil
}
