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

// Package fleet owns multi-rig fan-out orchestration and the mr-* doctor checks.
package fleet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrUnreachable is returned when a decode is attempted on an UNREACHABLE
// RigResult (Reachable==false). UNREACHABLE and degraded-but-reachable are
// intentionally distinct states (T-14-06 / Pitfall 5).
var ErrUnreachable = errors.New("fleet: rig is UNREACHABLE — no stdout to decode")

// StatusResult mirrors the statusReport JSON schema emitted by
// `abysslink status --json` on the remote rig (cmd_status.go:32-41).
// Fan-out decodes the remote stdout into this struct.
type StatusResult struct {
	Tailscale    string `json:"tailscale"`
	TailscaleIP  string `json:"tailscale_ip,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	TailscaleSSH string `json:"tailscale_ssh"`
	TailnetLock  string `json:"tailnet_lock"`
	Ntfy         string `json:"ntfy"`
	DiskEncrypt  string `json:"disk_encrypt"`
	Timestamp    string `json:"timestamp"`
}

// RemoteFinding mirrors the doctorFinding JSON schema emitted by
// `abysslink doctor --json` on the remote rig (cmd_doctor.go:30-36).
type RemoteFinding struct {
	Module   string `json:"module"`
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

// DecodeStatus decodes the remote `abysslink status --json` output from a
// RigResult's Stdout field.
//
// Return semantics (T-14-06 / Pitfall 5):
//   - UNREACHABLE (r.Reachable==false): returns ErrUnreachable; ok=false.
//   - Degraded-but-reachable (Reachable==true, invalid JSON): returns a decode
//     error with the raw stdout tail so callers can surface a warning; ok=false.
//     This is DISTINCT from UNREACHABLE — the rig was online but output was not
//     parseable (e.g. banner/MOTD contamination, schema mismatch).
//   - Success (Reachable==true, valid JSON): returns the decoded StatusResult; ok=true.
//
// Only r.Stdout is decoded — never stderr, where banners/MOTD may leak (Pitfall 5).
func DecodeStatus(r RigResult) (StatusResult, bool, error) {
	if !r.Reachable {
		return StatusResult{}, false, ErrUnreachable
	}
	var s StatusResult
	if err := json.Unmarshal([]byte(r.Stdout), &s); err != nil {
		tail := rawTail(r.Stdout, 120)
		return StatusResult{}, false, fmt.Errorf(
			"fleet: rig %q reachable but stdout not parseable as status JSON "+
				"(degraded-but-reachable); raw tail: %q; decode error: %w",
			r.Rig.Name, tail, err,
		)
	}
	return s, true, nil
}

// DecodeFindings decodes the remote `abysslink doctor --json` output from a
// RigResult's Stdout field.
//
// Return semantics are identical to DecodeStatus (see above).
func DecodeFindings(r RigResult) ([]RemoteFinding, bool, error) {
	if !r.Reachable {
		return nil, false, ErrUnreachable
	}
	var findings []RemoteFinding
	if err := json.Unmarshal([]byte(r.Stdout), &findings); err != nil {
		tail := rawTail(r.Stdout, 120)
		return nil, false, fmt.Errorf(
			"fleet: rig %q reachable but stdout not parseable as doctor JSON "+
				"(degraded-but-reachable); raw tail: %q; decode error: %w",
			r.Rig.Name, tail, err,
		)
	}
	return findings, true, nil
}

// rawTail returns up to n characters from the end of s, for surfacing in
// degraded-but-reachable warnings (Pitfall 5 diagnostic aid).
func rawTail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
