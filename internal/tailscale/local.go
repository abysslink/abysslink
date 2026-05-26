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

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/abysslink/abysslink/internal/shell"
)

// intermediate JSON structs used for tailscale status --json parsing.
type statusJSON struct {
	BackendState   string          `json:"BackendState"`
	Self           *peerStatusJSON `json:"Self"`
	Health         []string        `json:"Health"`
	MagicDNSSuffix string          `json:"MagicDNSSuffix"`
	CurrentTailnet *struct {
		Name           string `json:"Name"`
		MagicDNSSuffix string `json:"MagicDNSSuffix"`
	} `json:"CurrentTailnet"`
}

type peerStatusJSON struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
}

// LocalClient wraps the tailscale CLI for local daemon interaction.
type LocalClient struct {
	runner shell.Runner
}

// NewLocalClient returns a LocalClient using the given shell runner.
func NewLocalClient(runner shell.Runner) *LocalClient {
	return &LocalClient{runner: runner}
}

// Status returns the current tailscale status by running `tailscale status --json`.
func (c *LocalClient) Status(ctx context.Context) (*Status, error) {
	res, err := c.runner.Run(ctx, "tailscale", "status", "--json")
	if err != nil {
		return nil, fmt.Errorf("tailscale status: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("tailscale status exited %d: %s", res.ExitCode, res.Stderr)
	}

	var raw statusJSON
	if err := json.Unmarshal([]byte(res.Stdout), &raw); err != nil {
		return nil, fmt.Errorf("tailscale status: parse JSON: %w", err)
	}

	st := &Status{
		BackendState:   BackendState(raw.BackendState),
		Health:         raw.Health,
		MagicDNSSuffix: raw.MagicDNSSuffix,
	}

	if raw.Self != nil {
		ps, err := convertPeerStatus(raw.Self)
		if err != nil {
			return nil, fmt.Errorf("tailscale status: parse Self: %w", err)
		}
		st.Self = ps
	}

	if raw.CurrentTailnet != nil {
		st.CurrentTailnet = &TailnetInfo{
			Name:           raw.CurrentTailnet.Name,
			MagicDNSSuffix: raw.CurrentTailnet.MagicDNSSuffix,
		}
	}

	return st, nil
}

func convertPeerStatus(p *peerStatusJSON) (*PeerStatus, error) {
	ps := &PeerStatus{
		HostName: p.HostName,
		DNSName:  p.DNSName,
		Online:   p.Online,
	}
	for _, ipStr := range p.TailscaleIPs {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil, fmt.Errorf("parse IP %q: %w", ipStr, err)
		}
		ps.TailscaleIPs = append(ps.TailscaleIPs, addr)
	}
	return ps, nil
}

// IP returns the first Tailscale IP for this node, or empty string if none.
func (c *LocalClient) IP(ctx context.Context) (string, error) {
	st, err := c.Status(ctx)
	if err != nil {
		return "", err
	}
	if st.Self == nil || len(st.Self.TailscaleIPs) == 0 {
		return "", nil
	}
	return st.Self.TailscaleIPs[0].String(), nil
}

// Hostname returns the Tailscale hostname for this node.
func (c *LocalClient) Hostname(ctx context.Context) (string, error) {
	st, err := c.Status(ctx)
	if err != nil {
		return "", err
	}
	if st.Self == nil {
		return "", nil
	}
	return st.Self.HostName, nil
}

// Lock returns the Tailnet Lock status by running `tailscale lock status --json`.
func (c *LocalClient) Lock(ctx context.Context) (*LockStatus, error) {
	res, err := c.runner.Run(ctx, "tailscale", "lock", "status", "--json")
	if err != nil {
		return nil, fmt.Errorf("tailscale lock status: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("tailscale lock status exited %d: %s", res.ExitCode, res.Stderr)
	}

	var ls LockStatus
	if err := json.Unmarshal([]byte(res.Stdout), &ls); err != nil {
		return nil, fmt.Errorf("tailscale lock status: parse JSON: %w", err)
	}
	return &ls, nil
}

// Up runs `tailscale up` with the given options.
func (c *LocalClient) Up(ctx context.Context, opts UpOpts) error {
	args := []string{"up"}
	if opts.Hostname != "" {
		args = append(args, "--hostname="+opts.Hostname)
	}
	if opts.SSH {
		args = append(args, "--ssh")
	}
	if !opts.AcceptRoutes {
		args = append(args, "--accept-routes=false")
	}
	if opts.AdvertiseExitNode {
		args = append(args, "--advertise-exit-node")
	}

	res, err := c.runner.Run(ctx, "tailscale", args...)
	if err != nil {
		return fmt.Errorf("tailscale up: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("tailscale up exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}

// Set runs `tailscale set` with the given options.
func (c *LocalClient) Set(ctx context.Context, opts SetOpts) error {
	args := []string{"set"}
	if opts.Hostname != "" {
		args = append(args, "--hostname="+opts.Hostname)
	}
	if opts.AutoUpdate {
		args = append(args, "--auto-update")
	}

	res, err := c.runner.Run(ctx, "tailscale", args...)
	if err != nil {
		return fmt.Errorf("tailscale set: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("tailscale set exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}

// Down runs `tailscale down`.
func (c *LocalClient) Down(ctx context.Context) error {
	res, err := c.runner.Run(ctx, "tailscale", "down")
	if err != nil {
		return fmt.Errorf("tailscale down: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("tailscale down exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}
