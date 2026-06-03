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

package linux_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/platform"
	linuxpkg "github.com/abysslink/abysslink/internal/platform/linux"
)

func TestDistroDetection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		fixture    string
		wantDistro platform.Distro
		wantPkgMgr platform.PackageManager
	}{
		{"debian.txt", platform.DistroDebian, platform.PkgApt},
		{"ubuntu.txt", platform.DistroUbuntu, platform.PkgApt},
		{"fedora.txt", platform.DistroFedora, platform.PkgDnf},
		{"rhel.txt", platform.DistroRHEL, platform.PkgDnf},
		{"centos.txt", platform.DistroCentOS, platform.PkgDnf},
		{"arch.txt", platform.DistroArch, platform.PkgPacman},
		{"nixos.txt", platform.DistroNixOS, platform.PkgNix},
		{"unknown.txt", platform.DistroUnknown, platform.PackageManager("")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			f, err := os.Open("testdata/os-release/" + tc.fixture)
			require.NoError(t, err)
			defer func() { _ = f.Close() }()

			fields, err := linuxpkg.ParseOSRelease(f)
			require.NoError(t, err)

			gotDistro := linuxpkg.DetectDistro(fields)
			require.Equal(t, tc.wantDistro, gotDistro, "distro mismatch for %s", tc.fixture)

			gotPkgMgr := linuxpkg.DistroToPackageManager(gotDistro)
			require.Equal(t, tc.wantPkgMgr, gotPkgMgr, "package manager mismatch for %s", tc.fixture)
		})
	}
}
