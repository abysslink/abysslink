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

package tailscale

import "net/netip"

// BackendState is the state reported by tailscaled.
type BackendState string

// BackendState values.
const (
	StateRunning    BackendState = "Running"
	StateNeedsLogin BackendState = "NeedsLogin"
	StateStopped    BackendState = "Stopped"
	StateUnknown    BackendState = "Unknown"
)

// Status mirrors the fields we care about from `tailscale status --json`.
type Status struct {
	BackendState   BackendState
	Self           *PeerStatus
	Health         []string
	MagicDNSSuffix string
	CurrentTailnet *TailnetInfo
}

// PeerStatus holds the status of a single Tailscale peer (including Self).
type PeerStatus struct {
	HostName     string
	DNSName      string
	TailscaleIPs []netip.Addr
	Online       bool
}

// TailnetInfo holds metadata about the current tailnet.
type TailnetInfo struct {
	Name           string
	MagicDNSSuffix string
}

// LockStatus mirrors `tailscale lock status --json`.
type LockStatus struct {
	Enabled bool
}

// LockInitResult holds the output from `tailscale lock init`.
// Disablement secrets are captured in memory only — never written to disk.
type LockInitResult struct {
	DisablementSecrets []string // printed to stdout, never stored
	TrustedKeys        []string
}

// UpOpts are options for `tailscale up`.
type UpOpts struct {
	Hostname          string
	SSH               bool
	AcceptRoutes      bool
	AdvertiseExitNode bool
}

// SetOpts are options for `tailscale set`.
type SetOpts struct {
	Hostname   string
	AutoUpdate bool
}
