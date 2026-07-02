//go:build linux

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

package linux

import "testing"

// TestCryptCoversPath is the fail-closed disk-encryption regression test: the
// gate must key off the crypt ancestry of the device that actually hosts the
// TARGET path (root), not "any crypt device exists anywhere in the tree". A
// stray crypt node (encrypted swap, a plugged-in LUKS USB, a separate encrypted
// /home) must NOT make an unencrypted root report as encrypted.
func TestCryptCoversPath(t *testing.T) {
	tests := []struct {
		name    string
		devices []lsblkDevice
		want    bool
	}{
		{
			name: "LUKS root → encrypted",
			devices: []lsblkDevice{
				{Name: "sda", Type: "disk", Children: []lsblkDevice{
					{Name: "sda1", Type: "part", Children: []lsblkDevice{
						{Name: "sda1_crypt", Type: "crypt", MountPoint: "/"},
					}},
				}},
			},
			want: true,
		},
		{
			name: "LVM-on-LUKS root → encrypted (crypt is an ancestor)",
			devices: []lsblkDevice{
				{Name: "sda", Type: "disk", Children: []lsblkDevice{
					{Name: "sda2", Type: "part", Children: []lsblkDevice{
						{Name: "luks", Type: "crypt", Children: []lsblkDevice{
							{Name: "vg-root", Type: "lvm", MountPoint: "/"},
						}},
					}},
				}},
			},
			want: true,
		},
		{
			name: "unencrypted root but encrypted swap → NOT encrypted (the bug)",
			devices: []lsblkDevice{
				{Name: "sda", Type: "disk", Children: []lsblkDevice{
					{Name: "sda1", Type: "part", MountPoint: "/"},
					{Name: "sda2", Type: "part", Children: []lsblkDevice{
						{Name: "cryptswap", Type: "crypt", MountPoint: "[SWAP]"},
					}},
				}},
			},
			want: false,
		},
		{
			name: "unencrypted root but plugged-in LUKS USB → NOT encrypted",
			devices: []lsblkDevice{
				{Name: "sda", Type: "disk", Children: []lsblkDevice{
					{Name: "sda1", Type: "part", MountPoint: "/"},
				}},
				{Name: "sdb", Type: "disk", Children: []lsblkDevice{
					{Name: "sdb1", Type: "part", Children: []lsblkDevice{
						{Name: "usb_crypt", Type: "crypt", MountPoint: "/mnt/usb"},
					}},
				}},
			},
			want: false,
		},
		{
			name: "LUKS root but plaintext /home is deeper → root still counts as encrypted",
			devices: []lsblkDevice{
				{Name: "sda", Type: "disk", Children: []lsblkDevice{
					{Name: "sda1", Type: "part", Children: []lsblkDevice{
						{Name: "root_crypt", Type: "crypt", MountPoint: "/"},
					}},
					{Name: "sda2", Type: "part", MountPoint: "/home"},
				}},
			},
			want: true, // deepest mount covering "/" is the crypt root
		},
		{
			name:    "no mount covering root → NOT encrypted (fail closed)",
			devices: []lsblkDevice{{Name: "sda", Type: "disk", MountPoint: "/data"}},
			want:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cryptCoversPath("/", tc.devices); got != tc.want {
				t.Fatalf("cryptCoversPath(/) = %v, want %v", got, tc.want)
			}
		})
	}
}
