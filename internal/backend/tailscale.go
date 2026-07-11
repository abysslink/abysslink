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
	"context"
	"os"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tailscale"
)

// oauthSecretEnv is the environment variable holding the Tailscale admin OAuth
// client secret. The secret is never stored in abysslink.yaml or on disk.
const oauthSecretEnv = "ABYSSLINK_TS_OAUTH_SECRET" //nolint:gosec // env var name, not a secret value

// defaultSSHCheckPeriod is the immutable 12h SSH check period fallback.
// See DESIGN.md: this value cannot be raised without --accept-checkperiod-extension.
const defaultSSHCheckPeriod = 12 * time.Hour

// tailscaleAdapter is a pure pass-through adapter that wraps the concrete
// internal/tailscale clients behind the backend-neutral Client interface.
// It is the ONLY adapter (besides internal/tailscale/**) allowed to import
// internal/tailscale (depguard exempts internal/backend/**).
type tailscaleAdapter struct {
	local *tailscale.LocalClient
	lock  *tailscale.LockClient
	admin *tailscale.AdminClient
	cfg   *config.Config
}

// newTailscaleAdapter constructs a tailscaleAdapter from the given config and runner.
// The OAuth secret is read from the ABYSSLINK_TS_OAUTH_SECRET env var only —
// never from config or argv (CLAUDE.md: no secrets on argv).
func newTailscaleAdapter(cfg *config.Config, runner shell.Runner) *tailscaleAdapter {
	return &tailscaleAdapter{
		local: tailscale.NewLocalClient(runner),
		lock:  tailscale.NewLockClient(runner),
		admin: tailscale.NewAdminClient(
			cfg.Tailnet.Admin.Tailnet,
			cfg.Tailnet.Admin.OAuthClientID,
			os.Getenv(oauthSecretEnv),
		),
		cfg: cfg,
	}
}

// ── Core Client methods ────────────────────────────────────────────────────

// Status delegates to the wrapped LocalClient.Status.
func (a *tailscaleAdapter) Status(ctx context.Context) (*Status, error) {
	st, err := a.local.Status(ctx)
	if err != nil {
		return nil, err
	}
	// Convert internal/tailscale.Status → backend.Status (same field layout, repackaged).
	bst := &Status{
		BackendState:   State(st.BackendState),
		Health:         st.Health,
		MagicDNSSuffix: st.MagicDNSSuffix,
	}
	if st.Self != nil {
		bst.Self = &PeerStatus{
			HostName:     st.Self.HostName,
			DNSName:      st.Self.DNSName,
			TailscaleIPs: st.Self.TailscaleIPs,
			Online:       st.Self.Online,
		}
	}
	if st.CurrentTailnet != nil {
		bst.CurrentTailnet = &TailnetInfo{
			Name:           st.CurrentTailnet.Name,
			MagicDNSSuffix: st.CurrentTailnet.MagicDNSSuffix,
		}
	}
	return bst, nil
}

// IP delegates to the wrapped LocalClient.IP.
func (a *tailscaleAdapter) IP(ctx context.Context) (string, error) {
	return a.local.IP(ctx)
}

// Hostname delegates to the wrapped LocalClient.Hostname.
func (a *tailscaleAdapter) Hostname(ctx context.Context) (string, error) {
	return a.local.Hostname(ctx)
}

// SSHConfig parses cfg.Mobile.SSHCheckPeriod (a string, e.g. "12h") via
// time.ParseDuration; on empty or parse-error it falls back to the immutable
// 12h default so CheckPeriod is always non-zero (contract invariant #2).
func (a *tailscaleAdapter) SSHConfig() SSHConfig {
	if a.cfg.Mobile.SSHCheckPeriod != "" {
		d, err := time.ParseDuration(a.cfg.Mobile.SSHCheckPeriod)
		if err == nil && d > 0 {
			return SSHConfig{CheckPeriod: d}
		}
	}
	return SSHConfig{CheckPeriod: defaultSSHCheckPeriod}
}

// LockCapability returns LockFull — Tailscale fully supports Tailnet Lock
// (contract invariant #3).
func (a *tailscaleAdapter) LockCapability() LockCapability { return LockFull }

// Capabilities returns all-true for the Tailscale adapter.
// The Tailscale adapter implements Locker, AdminAPI, and ACLManager in full.
func (a *tailscaleAdapter) Capabilities() Capabilities {
	return Capabilities{
		Lock:            true,
		AdminAPI:        true,
		SSHCheck:        true,
		AuthKeys:        true,
		FunnelRejection: true,
		ACL:             true,
	}
}

// Up delegates to the wrapped LocalClient.Up.
func (a *tailscaleAdapter) Up(ctx context.Context, opts UpOpts) error {
	return a.local.Up(ctx, tailscale.UpOpts{
		Hostname:          opts.Hostname,
		SSH:               opts.SSH,
		AcceptRoutes:      opts.AcceptRoutes,
		AdvertiseExitNode: opts.AdvertiseExitNode,
	})
}

// Set delegates to the wrapped LocalClient.Set.
func (a *tailscaleAdapter) Set(ctx context.Context, opts SetOpts) error {
	return a.local.Set(ctx, tailscale.SetOpts{
		Hostname:   opts.Hostname,
		AutoUpdate: opts.AutoUpdate,
	})
}

// Down delegates to the wrapped LocalClient.Down.
func (a *tailscaleAdapter) Down(ctx context.Context) error {
	return a.local.Down(ctx)
}

// LiveTailnetLockStatus probes the LIVE Tailnet Lock state by shelling the
// tailscale CLI directly (`tailscale lock status --json`), independent of the
// configured backend.type. abysslink's bring-up always drives the tailscale
// client (`tailscale up` / `tailscale set --ssh`) regardless of backend.type, so
// security gates that must fail closed on a lock-off tailnet key off THIS live
// probe rather than the config-typed Client's Locker capability — a non-Locker
// backend adapter (Headscale / NetBird) must not make such a gate skippable
// while the tailscale client is still what brings SSH online (LOCK-BACKEND-01 /
// BKLG-01). A non-nil error means the state could not be determined (UNKNOWN).
//
// It lives in internal/backend because the depguard architecture rule forbids
// importing the concrete internal/tailscale package outside this package; CLI
// gates call this helper instead of constructing a LockClient themselves.
func LiveTailnetLockStatus(ctx context.Context, runner shell.Runner) (*LockStatus, error) {
	ls, err := tailscale.NewLockClient(runner).Status(ctx)
	if err != nil {
		return nil, err
	}
	return &LockStatus{Enabled: ls.Enabled}, nil
}

// ── Locker sub-interface ───────────────────────────────────────────────────

// LockStatus delegates to the wrapped LockClient.Status.
func (a *tailscaleAdapter) LockStatus(ctx context.Context) (*LockStatus, error) {
	ls, err := a.lock.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &LockStatus{Enabled: ls.Enabled}, nil
}

// LockInit delegates to the wrapped LockClient.Init.
func (a *tailscaleAdapter) LockInit(ctx context.Context, n int, shareSupport bool) (*LockInitResult, error) {
	r, err := a.lock.Init(ctx, n, shareSupport)
	if err != nil {
		return nil, err
	}
	return &LockInitResult{
		DisablementSecrets: r.DisablementSecrets,
		TrustedKeys:        r.TrustedKeys,
	}, nil
}

// LockSign delegates to the wrapped LockClient.Sign.
func (a *tailscaleAdapter) LockSign(ctx context.Context, key string) error {
	return a.lock.Sign(ctx, key)
}

// ── AdminAPI sub-interface ─────────────────────────────────────────────────

// Devices delegates to the wrapped AdminClient.Devices.
func (a *tailscaleAdapter) Devices(ctx context.Context) ([]Device, error) {
	devs, err := a.admin.Devices(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Device, len(devs))
	for i, d := range devs {
		result[i] = Device{
			ID:       d.ID,
			Name:     d.Name,
			Hostname: d.Hostname,
			Tags:     d.Tags,
		}
	}
	return result, nil
}

// TagDevice delegates to the wrapped AdminClient.TagDevice.
func (a *tailscaleAdapter) TagDevice(ctx context.Context, id string, tags []string) error {
	return a.admin.TagDevice(ctx, id, tags)
}

// DeleteDevice delegates to the wrapped AdminClient.DeleteDevice.
func (a *tailscaleAdapter) DeleteDevice(ctx context.Context, id string) error {
	return a.admin.DeleteDevice(ctx, id)
}

// CreateAuthKey delegates to the wrapped AdminClient.CreateAuthKey.
func (a *tailscaleAdapter) CreateAuthKey(ctx context.Context, tags []string) (string, error) {
	return a.admin.CreateAuthKey(ctx, tags)
}

// ── ACLManager sub-interface ───────────────────────────────────────────────

// GetACL delegates to the wrapped AdminClient.GetACL.
func (a *tailscaleAdapter) GetACL(ctx context.Context) ([]byte, string, error) {
	return a.admin.GetACL(ctx)
}

// SetACL delegates to the wrapped AdminClient.SetACL.
func (a *tailscaleAdapter) SetACL(ctx context.Context, acl []byte, etag string) error {
	return a.admin.SetACL(ctx, acl, etag)
}

// NewACLEditor delegates to tailscale.NewACLEditor.
func (a *tailscaleAdapter) NewACLEditor(raw []byte) (ACLEditor, error) {
	return tailscale.NewACLEditor(raw)
}

// DefaultACL delegates to tailscale.DefaultACL.
func (a *tailscaleAdapter) DefaultACL(owner, sshUser string) []byte {
	return tailscale.DefaultACL(owner, sshUser)
}

// Diff delegates to tailscale.Diff.
func (a *tailscaleAdapter) Diff(oldBytes, newBytes []byte) string {
	return tailscale.Diff(oldBytes, newBytes)
}
