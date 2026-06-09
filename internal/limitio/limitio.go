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

package limitio

import (
	"fmt"
	"io"
)

// MaxBackendBody is the maximum REST response body accepted from any backend
// or CLI remote call (Headscale, NetBird, GitHub releases).
// Chosen well above the largest legit response (~2 MB for a 1000-node fleet
// list) while preventing memory-exhaustion DoS (DOS-01).
const MaxBackendBody int64 = 8 * 1024 * 1024 // 8 MiB

// ErrSnippetMax is the byte cap for an HTTP error-response snippet included in
// an error message (e.g. a non-200 body). It is small on purpose: the snippet
// is only for operator-facing diagnostics, never decoded. Hoisted here (WR-03 /
// IN-01) so every error-path read shares one named constant instead of the
// magic literal 256 duplicated across cmd_upgrade.go and cmd_server_headscale.go.
const ErrSnippetMax int64 = 256

// ReadLimited reads at most n bytes from r. If the body exceeds n bytes it
// returns an explicit error — io.LimitReader alone silently truncates; the
// N+1 sentinel detects overflow before JSON decode (DOS-01).
//
// CORE-08: r is a plain io.Reader — ReadLimited never closes it. The caller
// retains ownership of any underlying Closer (resp.Body, *os.File, ...) and
// must close it itself (typically via defer at the call site).
func ReadLimited(r io.Reader, n int64) ([]byte, error) {
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

// ReadSnippet reads at most ErrSnippetMax bytes from r for use in an error
// message. Unlike ReadLimited it never returns an error: a snippet read is
// best-effort diagnostics on an already-failed request, so a truncated or empty
// snippet is acceptable. Routing error-path reads through this keeps every
// resp.Body read bounded by a named cap (WR-03 / IN-01).
func ReadSnippet(r io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(r, ErrSnippetMax))
	return string(data)
}
