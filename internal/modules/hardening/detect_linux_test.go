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

//go:build linux

package hardening

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUnderPath(t *testing.T) {
	assert.True(t, isUnderPath("/home/alice", "/home"))
	assert.True(t, isUnderPath("/home/alice", "/home/alice"))
	assert.False(t, isUnderPath("/tmp/work", "/home"))
	assert.False(t, isUnderPath("/home2/bob", "/home"))
}

func TestIsHomeEncrypted_CryptAncestor(t *testing.T) {
	// Simulates: sda → sda1 (crypt) → dm-0 (lvm) mounted at /home
	devices := []lsblkDevice{
		{
			Name: "sda",
			Type: "disk",
			Children: []lsblkDevice{
				{
					Name: "sda1",
					Type: "crypt",
					Children: []lsblkDevice{
						{
							Name:       "dm-0",
							Type:       "lvm",
							MountPoint: "/home",
						},
					},
				},
			},
		},
	}
	assert.True(t, isHomeEncrypted("/home/alice", devices), "crypt ancestor → encrypted")
}

func TestIsHomeEncrypted_NoCrypt(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name: "sda",
			Type: "disk",
			Children: []lsblkDevice{
				{
					Name:       "sda1",
					Type:       "part",
					MountPoint: "/home",
				},
			},
		},
	}
	assert.False(t, isHomeEncrypted("/home/alice", devices), "plain partition → not encrypted")
}

func TestIsHomeEncrypted_HomeNotMounted(t *testing.T) {
	// Root is encrypted but home isn't a separate mount (/ contains /home).
	devices := []lsblkDevice{
		{
			Name: "sda1",
			Type: "crypt",
			Children: []lsblkDevice{
				{
					Name:       "dm-0",
					Type:       "lvm",
					MountPoint: "/",
				},
			},
		},
	}
	// /home/alice is under / which is on an encrypted device.
	assert.True(t, isHomeEncrypted("/home/alice", devices))
}
