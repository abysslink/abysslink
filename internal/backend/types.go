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
	"net/netip"
	"time"
)

// BackendState is the state reported by tailscaled.
// Moved verbatim from internal/tailscale/types.go:21-28.
type BackendState string

// BackendState values.
const (
	StateRunning    BackendState = "Running"
	StateNeedsLogin BackendState = "NeedsLogin"
	StateStopped    BackendState = "Stopped"
	StateUnknown    BackendState = "Unknown"
)

// Status mirrors the fields we care about from `tailscale status --json`.
// Moved verbatim from internal/tailscale/types.go:31-38.
type Status struct {
	BackendState   BackendState
	Self           *PeerStatus
	Health         []string
	MagicDNSSuffix string
	CurrentTailnet *TailnetInfo
}

// PeerStatus holds the status of a single Tailscale peer (including Self).
// Moved verbatim from internal/tailscale/types.go:41-46.
type PeerStatus struct {
	HostName     string
	DNSName      string
	TailscaleIPs []netip.Addr
	Online       bool
}

// TailnetInfo holds metadata about the current tailnet.
// Moved verbatim from internal/tailscale/types.go:49-52.
type TailnetInfo struct {
	Name           string
	MagicDNSSuffix string
}

// LockStatus mirrors `tailscale lock status --json`.
// Moved verbatim from internal/tailscale/types.go:55-57.
type LockStatus struct {
	Enabled bool
}

// LockInitResult holds the output from `tailscale lock init`.
// Disablement secrets are captured in memory only — never written to disk.
// Moved verbatim from internal/tailscale/types.go:60-64.
type LockInitResult struct {
	DisablementSecrets []string // printed to stdout, never stored
	TrustedKeys        []string
}

// UpOpts are options for `tailscale up`.
// Moved verbatim from internal/tailscale/types.go:66-73.
type UpOpts struct {
	Hostname          string
	SSH               bool
	AcceptRoutes      bool
	AdvertiseExitNode bool
}

// SetOpts are options for `tailscale set`.
// Moved verbatim from internal/tailscale/types.go:75-78.
type SetOpts struct {
	Hostname   string
	AutoUpdate bool
}

// Device represents a device in a Tailscale tailnet.
// Moved verbatim from internal/tailscale/admin.go:33-38.
type Device struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Hostname string   `json:"hostname"`
	Tags     []string `json:"tags"`
}

// LockCapability describes the Tailnet Lock capability of this backend.
type LockCapability string

// LockCapability values.
const (
	// LockFull means the backend fully supports Tailnet Lock (Tailscale).
	LockFull LockCapability = "Full"
	// LockNone means the backend has no Tailnet Lock support (Headscale, NetBird).
	LockNone LockCapability = "None"
)

// SSHConfig carries the SSH check-period configuration derived from the
// parsed config. CheckPeriod is always non-zero (contract invariant #2).
type SSHConfig struct {
	CheckPeriod time.Duration // non-zero invariant; derived from cfg.Mobile.SSHCheckPeriod + 12h default
}
