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

package cli

import (
	"context"
	"fmt"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// floorKind classifies the CVE type so the FATAL message can give kind-appropriate
// remediation guidance (D-10).
type floorKind int

const (
	// kindProtocol: vulnerability in the tool's own protocol or auth layer.
	// Remediation: upgrade the tool binary to >= minVer.
	kindProtocol floorKind = iota
	// kindStdlibVendored: vulnerability in a vendored Go stdlib or dependency.
	// Remediation: upgrade the tool AND/OR rebuild against the patched stdlib.
	kindStdlibVendored
)

// versionFloor describes a minimum-safe version for a component that doctor
// should probe.  The table is data-driven so Tailscale / tmux / mosh floors
// can be added without new detector functions (D-08).
type versionFloor struct {
	component string    // human-readable name (e.g. "ntfy")
	binary    string    // executable to probe (e.g. "ntfy")
	verArgs   []string  // arguments to get the version string (e.g. ["--version"])
	minVer    string    // minimum safe version (semver, no "v" prefix)
	cve       string    // CVE identifier (e.g. "CVE-2026-39087")
	cvss      string    // CVSS score string (e.g. "9.8")
	kind      floorKind // kindProtocol or kindStdlibVendored
	checkID   string    // stable Finding.Check ID used by findingFix map (e.g. "ntfy-version")
}

// versionFloors is the package-level floor table.  Add rows here to extend
// coverage; the detector loop handles them automatically.
//
// Only the ntfy row is live in this phase.  Tailscale / tmux / mosh rows are
// deferred scaffolding — add rows when those floors are researched (D-08).
var versionFloors = []versionFloor{
	{
		component: "ntfy",
		binary:    "ntfy",
		verArgs:   []string{"--version"},
		minVer:    "2.21",
		cve:       "CVE-2026-39087",
		cvss:      "9.8",
		kind:      kindProtocol,
		checkID:   "ntfy-version",
	},
}

// versionFloorFindings probes each entry in versionFloors via the supplied
// shell.Runner and returns a []modules.Finding slice.
//
// Severity mapping (fail-honest — uncertainty degrades toward MORE severe):
//   - version < minVer  → SeverityFatal   (known-vulnerable; message names CVE + CVSS)
//   - version >= minVer → SeverityOK
//   - exec error        → SeverityWarning (binary absent or unprobeable)
//   - unparseable output → SeverityWarning (fail-honest; never silent pass — T-23-11)
//
// The detector is wired into collectDoctorFindings by Plan 04; it is NOT wired
// here (D-11: remediation text lives in findingFix, not in the detector message).
func versionFloorFindings(ctx context.Context, runner shell.Runner) []modules.Finding {
	var findings []modules.Finding

	for _, f := range versionFloors {
		findings = append(findings, probeFloor(ctx, runner, f))
	}

	return findings
}

// probeFloor executes one version-floor check and returns a single Finding.
func probeFloor(ctx context.Context, runner shell.Runner, f versionFloor) modules.Finding {
	// Probe via shell.Runner — no os/exec, no sh -c (CLAUDE.md hard rule, T-23-10).
	res, err := runner.Run(ctx, f.binary, f.verArgs...)
	if err != nil {
		return modules.Finding{
			Module:   "cli",
			Check:    f.checkID,
			Severity: modules.SeverityWarning,
			Message: fmt.Sprintf(
				"%s: could not probe version (%q --version failed) — version is unknown; upgrade to >= %s (%s, CVSS %s) to be safe",
				f.checkID, f.binary, f.minVer, f.cve, f.cvss,
			),
		}
	}

	// Parse version from combined stdout+stderr using the package-level versionRe
	// (cmd_init.go:55) — reuse; do NOT add a new regex (D-09).
	combined := res.Stdout + res.Stderr
	ver := versionRe.FindString(combined)
	if ver == "" {
		return modules.Finding{
			Module:   "cli",
			Check:    f.checkID,
			Severity: modules.SeverityWarning,
			Message: fmt.Sprintf(
				"%s: could not parse version from output %q — version unknown; upgrade to >= %s (%s, CVSS %s) to be safe",
				f.checkID, combined, f.minVer, f.cve, f.cvss,
			),
		}
	}

	// Compare with floor using the package-level semverLT (cmd_server_headscale.go:1224).
	// D-09: reuse this comparator; do NOT define a third semver function.
	if semverLT(ver, f.minVer) {
		msg := fatalMessage(f, ver)
		return modules.Finding{
			Module:   "cli",
			Check:    f.checkID,
			Severity: modules.SeverityFatal,
			Message:  msg,
		}
	}

	return modules.Finding{
		Module:   "cli",
		Check:    f.checkID,
		Severity: modules.SeverityOK,
		Message:  fmt.Sprintf("%s: %s meets minimum v%s floor (no known CVE)", f.checkID, ver, f.minVer),
	}
}

// fatalMessage builds the kind-appropriate FATAL message (D-10).
// Protocol CVEs: instruct to upgrade the tool binary.
// Stdlib-vendored CVEs: additionally note that a Go rebuild against patched stdlib closes it.
func fatalMessage(f versionFloor, ver string) string {
	base := fmt.Sprintf(
		"%s: %s %s is below minimum v%s (%s, CVSS %s unauthenticated RCE) — upgrade %s to >= %s",
		f.checkID, f.component, ver, f.minVer, f.cve, f.cvss, f.component, f.minVer,
	)
	switch f.kind {
	case kindStdlibVendored:
		return base + "; alternatively rebuild against a patched Go stdlib (vendored dependency)"
	default: // kindProtocol
		return base
	}
}
