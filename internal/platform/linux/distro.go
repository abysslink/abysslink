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

import (
	"bufio"
	"io"
	"strings"

	"github.com/abysslink/abysslink/internal/platform"
)

// ParseOSRelease parses a reader containing os-release key=value content.
// Returns a map of key -> unquoted value.
func ParseOSRelease(r io.Reader) (map[string]string, error) {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := line[idx+1:]
		// Strip surrounding double-quotes.
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		fields[key] = val
	}
	return fields, scanner.Err()
}

// distroByID maps an os-release ID value to its Distro constant.
var distroByID = map[string]platform.Distro{
	"debian":    platform.DistroDebian,
	"ubuntu":    platform.DistroUbuntu,
	"fedora":    platform.DistroFedora,
	"rhel":      platform.DistroRHEL,
	"centos":    platform.DistroCentOS,
	"rocky":     platform.DistroRHEL,
	"almalinux": platform.DistroRHEL,
	"arch":      platform.DistroArch,
	"manjaro":   platform.DistroArch,
	"nixos":     platform.DistroNixOS,
}

// distroByIDLike maps an os-release ID_LIKE token to its Distro constant.
// Narrower than distroByID: derivative-specific IDs (rocky, manjaro, ...) never
// appear in ID_LIKE, only their upstream family names.
var distroByIDLike = map[string]platform.Distro{
	"debian": platform.DistroDebian,
	"ubuntu": platform.DistroUbuntu,
	"fedora": platform.DistroFedora,
	"rhel":   platform.DistroRHEL,
	"centos": platform.DistroCentOS,
	"arch":   platform.DistroArch,
}

// DetectDistro maps the ID and ID_LIKE fields from os-release to a Distro constant.
// Falls back to DistroUnknown if unrecognised.
func DetectDistro(fields map[string]string) platform.Distro {
	id := strings.ToLower(strings.TrimSpace(fields["ID"]))
	if d, ok := distroByID[id]; ok {
		return d
	}

	// Fall back to ID_LIKE inspection.
	idLike := strings.ToLower(strings.TrimSpace(fields["ID_LIKE"]))
	for _, like := range strings.Fields(idLike) {
		if d, ok := distroByIDLike[like]; ok {
			return d
		}
	}

	return platform.DistroUnknown
}

// DistroToPackageManager maps a Distro to its package manager.
func DistroToPackageManager(d platform.Distro) platform.PackageManager {
	switch d {
	case platform.DistroDebian, platform.DistroUbuntu:
		return platform.PkgApt
	case platform.DistroFedora, platform.DistroRHEL, platform.DistroCentOS:
		return platform.PkgDnf
	case platform.DistroArch:
		return platform.PkgPacman
	case platform.DistroNixOS:
		return platform.PkgNix
	default:
		return platform.PackageManager("")
	}
}
