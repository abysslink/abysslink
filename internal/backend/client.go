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

import "context"

// Client is the backend-neutral interface consumed by all v1 modules and CLI
// commands. It corresponds to the Tailscale LocalClient method set plus the
// backend metadata getters. ctx is the first arg on all non-getter methods.
type Client interface {
	// Status returns the current backend state.
	Status(ctx context.Context) (*Status, error)
	// IP returns the first Tailscale/backend IP for this node (contract #1: non-empty).
	IP(ctx context.Context) (string, error)
	// Hostname returns the backend hostname for this node.
	Hostname(ctx context.Context) (string, error)
	// SSHConfig returns the SSH configuration (contract #2: CheckPeriod non-zero).
	SSHConfig() SSHConfig
	// LockCapability returns the Tailnet Lock capability (contract #3: Full for Tailscale).
	LockCapability() LockCapability
	// Capabilities returns the full declarative capability set for this backend.
	Capabilities() Capabilities
	// Up brings the backend daemon up with the given options.
	Up(ctx context.Context, opts UpOpts) error
	// Set applies daemon settings.
	Set(ctx context.Context, opts SetOpts) error
	// Down brings the backend daemon down.
	Down(ctx context.Context) error
}

// Locker is the optional sub-interface for backends that support Tailnet Lock.
// Type-assert Client → Locker before calling; gate on Capabilities().Lock.
type Locker interface {
	// LockStatus returns the current Tailnet Lock status.
	LockStatus(ctx context.Context) (*LockStatus, error)
	// LockInit initializes Tailnet Lock, generating n disablement secrets.
	LockInit(ctx context.Context, n int, shareSupport bool) (*LockInitResult, error)
	// LockSign signs a node key into the lock.
	LockSign(ctx context.Context, key string) error
}

// AdminAPI is the optional sub-interface for backends that support device
// management via an admin API. Gate on Capabilities().AdminAPI.
type AdminAPI interface {
	// Devices returns the list of devices in the tailnet.
	Devices(ctx context.Context) ([]Device, error)
	// TagDevice sets the tags for a device.
	TagDevice(ctx context.Context, id string, tags []string) error
	// DeleteDevice removes a device from the tailnet.
	DeleteDevice(ctx context.Context, id string) error
	// CreateAuthKey creates a pre-authorized auth key with the given tags.
	CreateAuthKey(ctx context.Context, tags []string) (string, error)
}

// ACLManager is the optional sub-interface for backends that support ACL
// management. Gate on Capabilities().ACL.
type ACLManager interface {
	// GetACL returns the current ACL HuJSON and ETag.
	GetACL(ctx context.Context) (raw []byte, etag string, err error)
	// SetACL posts a new ACL. Uses ETag for optimistic concurrency.
	SetACL(ctx context.Context, acl []byte, etag string) error
	// NewACLEditor returns an editor for the given HuJSON bytes.
	NewACLEditor(raw []byte) (ACLEditor, error)
	// DefaultACL returns the minimal safe ACL for abysslink.
	DefaultACL(owner, sshUser string) []byte
	// Diff returns a unified diff string between old and new HuJSON/JSON bytes.
	Diff(oldBytes, newBytes []byte) string
}

// ACLEditor edits a Tailscale HuJSON ACL document idempotently.
type ACLEditor interface {
	// Bytes returns the current JSON document.
	Bytes() []byte
	// EnsureTagOwners ensures tag:mobile and tag:laptop both list owner.
	EnsureTagOwners(owner string) error
	// EnsureGrant ensures the mobile→laptop grant exists.
	EnsureGrant() error
	// EnsureSSHRule ensures the SSH rule letting the tagged phone reach the rig.
	// (checkPeriod is retained for compatibility; the tailscale editor emits an
	// accept rule for tag:mobile, which carries no checkPeriod — see its impl.)
	EnsureSSHRule(owner, sshUser, checkPeriod string) error
}
