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

// Package platform defines the Platform interface — the single abstraction over macOS and Linux
// system operations (package management, services, keychain, disk encryption, firewall).
package platform

import "context"

// Distro identifies a Linux distribution family.
type Distro string

// Distro values for supported Linux distributions.
const (
	DistroDebian  Distro = "debian"
	DistroUbuntu  Distro = "ubuntu"
	DistroFedora  Distro = "fedora"
	DistroRHEL    Distro = "rhel"
	DistroCentOS  Distro = "centos"
	DistroArch    Distro = "arch"
	DistroNixOS   Distro = "nixos"
	DistroUnknown Distro = "unknown"
)

// PackageManager identifies the package manager for a distro.
type PackageManager string

// PackageManager values for supported package managers.
const (
	PkgApt    PackageManager = "apt"
	PkgDnf    PackageManager = "dnf"
	PkgPacman PackageManager = "pacman"
	PkgNix    PackageManager = "nix"
	PkgBrew   PackageManager = "brew"
)

// ServiceStatus represents the runtime state of a service.
type ServiceStatus string

// ServiceStatus values.
const (
	ServiceRunning ServiceStatus = "running"
	ServiceStopped ServiceStatus = "stopped"
	ServiceUnknown ServiceStatus = "unknown"
)

// DiskState represents disk encryption status.
type DiskState string

// DiskState values.
const (
	DiskEncrypted   DiskState = "encrypted"
	DiskUnencrypted DiskState = "unencrypted"
	DiskUnknown     DiskState = "unknown"
)

// KeepAwakeMode controls system sleep prevention.
type KeepAwakeMode string

// KeepAwakeMode values.
const (
	KeepAwakeDisplay KeepAwakeMode = "display"
	KeepAwakeSystem  KeepAwakeMode = "system"
	KeepAwakeOff     KeepAwakeMode = "off"
)

// ServiceSpec describes a managed background service.
type ServiceSpec struct {
	Label      string            // launchd label / systemd unit name
	Args       []string          // argv[0] is the binary, rest are args
	Env        map[string]string // additional environment variables
	StdoutPath string            // path for stdout log (empty = /dev/null)
	StderrPath string            // path for stderr log (empty = /dev/null)
	KeepAlive  bool              // restart on exit
	RunAtLoad  bool              // start immediately on install
}

// FirewallController manages host firewall rules.
type FirewallController interface {
	AllowPort(ctx context.Context, port int, proto string) error
	DenyPort(ctx context.Context, port int, proto string) error
	Status(ctx context.Context) (string, error)
}

// AppFirewall is an optional capability for per-application firewalls (the macOS
// Application Firewall). A FirewallController MAY implement it; callers must
// type-assert. It exists because macOS gates incoming connections per signed
// binary, not per port — so an unsigned Homebrew binary (e.g. mosh-server) is
// blocked on first incoming connection until explicitly allowed. Linux's
// per-port firewall does not implement this capability.
type AppFirewall interface {
	// AllowApp permits incoming connections to the binary at binaryPath.
	AllowApp(ctx context.Context, binaryPath string) error
	// IsAppAllowed reports whether incoming connections to binaryPath are permitted.
	IsAppAllowed(ctx context.Context, binaryPath string) (bool, error)
}

// RangeFirewall is an optional capability for per-port-range firewalls (Linux
// ufw/iptables). A FirewallController MAY implement it; callers must type-assert.
// macOS's per-application firewall does not implement this capability.
type RangeFirewall interface {
	// AllowPortRange opens the inclusive [lo,hi] port range for proto ("udp"/"tcp").
	AllowPortRange(ctx context.Context, lo, hi int, proto string) error
	// IsPortRangeAllowed reports whether [lo,hi]/proto is already permitted.
	IsPortRangeAllowed(ctx context.Context, lo, hi int, proto string) (bool, error)
}

// PathLinker is an optional Platform capability that makes an installed binary
// resolvable on the system base PATH used by non-login shells — notably the
// shell Tailscale SSH execs remote commands in. On macOS, Homebrew's bin dir
// (/opt/homebrew/bin or /usr/local/bin on Intel) is absent from that PATH, so
// binaries are symlinked into /usr/local/bin (which is on the base PATH for
// sh/bash/zsh/fish). Linux package managers install onto the base PATH already,
// so the Linux Platform does not implement this capability.
type PathLinker interface {
	// SymlinkIntoSystemPath symlinks binaryPath into a base-PATH directory,
	// keyed by its base name. Idempotent.
	SymlinkIntoSystemPath(ctx context.Context, binaryPath string) error
	// IsOnSystemPath reports whether a binary named name is resolvable on the
	// system base PATH (i.e. the abysslink-managed symlink resolves).
	IsOnSystemPath(ctx context.Context, name string) (bool, error)
}

// Platform abstracts macOS and Linux system operations.
type Platform interface {
	OS() string
	Distro() Distro
	PackageManager() PackageManager
	InstallPackage(ctx context.Context, name string) error
	RemovePackage(ctx context.Context, name string) error
	ServiceInstall(ctx context.Context, spec ServiceSpec) error
	ServiceUninstall(ctx context.Context, label string) error
	ServiceStart(ctx context.Context, label string) error
	ServiceStop(ctx context.Context, label string) error
	ServiceStatus(ctx context.Context, label string) (ServiceStatus, error)
	DiskEncryptionStatus(ctx context.Context) (DiskState, error)
	Firewall() FirewallController
	KeepAwake(ctx context.Context, mode KeepAwakeMode) error
}
