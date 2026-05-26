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
