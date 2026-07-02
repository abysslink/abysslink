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
	"strings"

	"github.com/abysslink/abysslink/internal/config"
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

// floorSeverity selects the Finding severity reported when a probed version
// sits below the floor. The zero value is fatal so every pre-existing CVE row
// keeps its FATAL behavior without edits (regression-guarded in tests).
type floorSeverity int

const (
	// floorSevFatal: below floor → SeverityFatal (known-vulnerable CVE rows).
	floorSevFatal floorSeverity = iota
	// floorSevWarn: below floor → SeverityWarning (capability floors — the
	// feature degrades but the system stays safe and operable, D-27).
	floorSevWarn
)

// finding maps a floorSeverity to the modules severity for a below-floor hit.
func (s floorSeverity) finding() modules.Severity {
	if s == floorSevWarn {
		return modules.SeverityWarning
	}
	return modules.SeverityFatal
}

// versionFloor describes a minimum-safe version for a component that doctor
// should probe.  The table is data-driven so Tailscale / tmux / mosh floors
// can be added without new detector functions (D-08).
type versionFloor struct {
	component string        // human-readable name (e.g. "ntfy")
	binary    string        // executable to probe (e.g. "ntfy")
	verArgs   []string      // arguments to get the version string (e.g. ["--version"])
	minVer    string        // minimum safe version (semver, no "v" prefix)
	cve       string        // CVE identifier (e.g. "CVE-2026-39087"); "" = capability floor
	cvss      string        // CVSS score string (e.g. "9.8")
	kind      floorKind     // kindProtocol or kindStdlibVendored
	checkID   string        // stable Finding.Check ID used by findingFix map (e.g. "ntfy-version")
	severity  floorSeverity // below-floor severity; zero value = FATAL (CVE rows)

	// applies gates the row on the active configuration. When nil the row always
	// probes (tmux, Tailscale). When set and it returns false the component is
	// not part of this install (e.g. the NetBird client floor on a Tailscale-
	// backend rig, or EternalTerminal when disabled): the binary is NOT probed
	// and the row reports SeverityOK "not configured" — an absent binary for a
	// component the operator never enabled must never degrade doctor to WARN and
	// strand the 0-exit "healthy" state.
	applies func(*config.Config) bool
}

// versionFloors is the package-level floor table.  Add rows here to extend
// coverage; the detector loop handles them automatically.
//
// ntfy is a CVE floor (FATAL below). tmux is a capability floor (WARN below —
// D-27: the session registry is optional, the daemon still runs). Tailscale /
// mosh rows remain deferred scaffolding — add rows when those floors are
// researched (D-08).
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
		applies:   func(c *config.Config) bool { return c.Modules.Ntfy.Enabled },
	},
	{
		component: "tmux",
		binary:    "tmux",
		verArgs:   []string{"-V"},
		minVer:    "3.2",
		checkID:   "tmux-version",
		severity:  floorSevWarn, // D-27: registry is optional — never FATAL
	},
	{
		// Tailscale transport floor (SUPL-04): below 1.98.1 is a FATAL
		// fail-closed gate — a downgraded tailscaled is an elevation risk.
		// No CVE id is cited (capability/security-boundary floor), so the
		// FATAL message uses the no-CVE branch in fatalMessage.
		component: "Tailscale",
		binary:    "tailscale",
		verArgs:   []string{"version"},
		minVer:    "1.98.1",
		checkID:   "tailscale-version",
		// severity zero value = floorSevFatal (fail-closed).
	},
	{
		// NetBird CLIENT floor (SUPL-04): distinct from the server-side
		// nb-version check in netbird_doctor.go. Below 0.57.0 is FATAL.
		component: "NetBird (client)",
		binary:    "netbird",
		verArgs:   []string{"version"},
		minVer:    "0.57.0",
		checkID:   "nb-client-version",
		// severity zero value = floorSevFatal (fail-closed).
		// Only relevant on a NetBird-backend rig; a stock Tailscale install has
		// no netbird binary and must not be permanently WARNed for its absence.
		applies: func(c *config.Config) bool { return c.Backend.Type == "netbird" },
	},
	{
		// EternalTerminal prefer-mosh capability floor (SUPL-04): below 6.2.0
		// is WARN, never FATAL — mosh provides a working fallback transport.
		component: "EternalTerminal",
		binary:    "et",
		verArgs:   []string{"--version"},
		minVer:    "6.2.0",
		checkID:   "et-version",
		severity:  floorSevWarn,
		// Only relevant when the EternalTerminal module is enabled (disabled by
		// default); otherwise the `et` binary is legitimately absent.
		applies: func(c *config.Config) bool { return c.Modules.EternalTerminal.Enabled },
	},
}

// versionFloorFindings probes each entry in versionFloors via the supplied
// shell.Runner and returns a []modules.Finding slice.
//
// Severity mapping (fail-honest — uncertainty degrades toward MORE severe):
//   - version < minVer  → SeverityFatal   (known-vulnerable; message names CVE + CVSS)
//   - version >= minVer → SeverityOK
//   - exec error        → SeverityWarning (binary absent or unprobeable)
//   - non-zero exit     → SeverityWarning (probe failed; any N.N token in its
//     output is untrustworthy — never a silent pass)
//   - unparseable output → SeverityWarning (fail-honest; never silent pass — T-23-11)
//
// The detector is wired into collectDoctorFindings by Plan 04; it is NOT wired
// here (D-11: remediation text lives in findingFix, not in the detector message).
//
// cfg gates each row on relevance (see versionFloor.applies): a component the
// active config never enables reports OK "not configured" instead of probing an
// absent binary and permanently WARNing — otherwise a stock Tailscale install
// (no netbird / no EternalTerminal) could never reach the 0-exit "healthy" state.
func versionFloorFindings(ctx context.Context, cfg *config.Config, runner shell.Runner) []modules.Finding {
	if cfg == nil {
		cfg = config.Defaults()
	}

	var findings []modules.Finding

	for _, f := range versionFloors {
		if f.applies != nil && !f.applies(cfg) {
			findings = append(findings, notApplicableFloorFinding(f))
			continue
		}
		findings = append(findings, probeFloor(ctx, runner, f))
	}

	return findings
}

// notApplicableFloorFinding reports an OK finding for a floor row whose component
// is not part of the active configuration. The binary is deliberately NOT probed
// so an absent binary for a never-enabled component cannot degrade doctor to WARN.
func notApplicableFloorFinding(f versionFloor) modules.Finding {
	return modules.Finding{
		Module:   "cli",
		Check:    f.checkID,
		Severity: modules.SeverityOK,
		Message:  fmt.Sprintf("%s: %s is not configured on this rig — version floor not applicable", f.checkID, f.component),
	}
}

// probeFloor executes one version-floor check and returns a single Finding.
func probeFloor(ctx context.Context, runner shell.Runner, f versionFloor) modules.Finding {
	// Probe via shell.Runner — no os/exec, no sh -c (CLAUDE.md hard rule, T-23-10).
	// ExecRunner normalizes a non-zero exit to (Result, nil), so the exit code
	// must be checked explicitly: a failing binary that happens to print an
	// N.N token must degrade to WARN, never parse into a silent SeverityOK
	// (fail-honest ladder — mirrors the daemon supervisor's versionGate).
	res, err := runner.Run(ctx, f.binary, f.verArgs...)
	if err != nil || res.ExitCode != 0 {
		detail := fmt.Sprintf("could not probe version (%q %s failed)", f.binary, strings.Join(f.verArgs, " "))
		if err == nil {
			detail = fmt.Sprintf("could not probe version (%q %s exited %d)", f.binary, strings.Join(f.verArgs, " "), res.ExitCode)
		}
		return modules.Finding{
			Module:   "cli",
			Check:    f.checkID,
			Severity: modules.SeverityWarning,
			Message:  probeFailMessage(f, detail),
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
			Message:  probeFailMessage(f, fmt.Sprintf("could not parse version from output %q", combined)),
		}
	}

	// Compare with floor using the package-level semverLT (cmd_server_headscale.go:1224).
	// D-09: reuse this comparator; do NOT define a third semver function. The
	// matched token is normalized first so the tmux "3.6b" letter-suffix
	// release format never silently parses its minor component to 0.
	if semverLT(normalizeFloorVersion(ver), f.minVer) {
		return modules.Finding{
			Module:   "cli",
			Check:    f.checkID,
			Severity: f.severity.finding(),
			Message:  belowFloorMessage(f, ver),
		}
	}

	okDetail := "no known CVE"
	if f.cve == "" {
		okDetail = "capability floor met"
	}
	return modules.Finding{
		Module:   "cli",
		Check:    f.checkID,
		Severity: modules.SeverityOK,
		Message:  fmt.Sprintf("%s: %s meets minimum v%s floor (%s)", f.checkID, ver, f.minVer, okDetail),
	}
}

// normalizeFloorVersion strips a trailing lowercase-letter suffix from a
// matched version token ("3.6b" → "3.6" — the tmux release format, mirroring
// modules/tmux parseTmuxVersion) so semverParts never silently parses the
// suffixed component to 0. Pre-release suffixes ("2.21.0-beta") are
// unaffected: semverParts already cuts at "-"/"+".
func normalizeFloorVersion(ver string) string {
	return strings.TrimRight(ver, "abcdefghijklmnopqrstuvwxyz")
}

// probeFailMessage explains an unprobeable or unparseable version per the
// fail-honest ladder (uncertainty degrades to WARN, never a silent pass —
// T-23-11). CVE rows name the CVE; capability rows name what needs the floor.
func probeFailMessage(f versionFloor, detail string) string {
	if f.cve != "" {
		return fmt.Sprintf("%s: %s — version is unknown; upgrade to >= %s (%s, CVSS %s) to be safe",
			f.checkID, detail, f.minVer, f.cve, f.cvss)
	}
	if f.checkID == "tmux-version" {
		return fmt.Sprintf("%s: %s — version is unknown; the session registry needs %s >= %s (D-27)",
			f.checkID, detail, f.component, f.minVer)
	}
	return fmt.Sprintf("%s: %s — version is unknown; upgrade %s to >= %s to meet the floor",
		f.checkID, detail, f.component, f.minVer)
}

// belowFloorMessage routes a below-floor hit to the kind-appropriate message:
// CVE rows get the FATAL remediation, capability rows the WARN degradation.
func belowFloorMessage(f versionFloor, ver string) string {
	if f.severity == floorSevWarn {
		return warnMessage(f, ver)
	}
	return fatalMessage(f, ver)
}

// warnMessage builds the WARN-severity capability-floor message: it names the
// found version, the floor, and what degrades — the system stays operable, so
// this is never a FATAL.
//
// The tmux session-registry floor (D-26/D-27) keeps its bespoke wording; every
// other capability row (e.g. EternalTerminal prefer-mosh) gets a generic
// "below floor — capability degraded, fallback exists" message so a new WARN
// row never inherits tmux-specific copy.
func warnMessage(f versionFloor, ver string) string {
	if f.checkID == "tmux-version" {
		return fmt.Sprintf(
			"%s: %s %s is below the %s capability floor — the session registry requires tmux >= %s "+
				"(attach-session -f client flags); below it notifications lose session identity and "+
				"GET /sessions reports unsupported; the daemon still runs (D-26/D-27)",
			f.checkID, f.component, ver, f.minVer, f.minVer,
		)
	}
	return fmt.Sprintf(
		"%s: %s %s is below the v%s capability floor — upgrade %s to >= %s; "+
			"a working fallback exists so this is advisory, not fail-closed",
		f.checkID, f.component, ver, f.minVer, f.component, f.minVer,
	)
}

// fatalMessage builds the kind-appropriate FATAL message (D-10).
// Protocol CVEs: instruct to upgrade the tool binary.
// Stdlib-vendored CVEs: additionally note that a Go rebuild against patched stdlib closes it.
// No-CVE security floors (e.g. Tailscale 1.98.1): a plain "below minimum —
// upgrade" message; never fabricate a "(, CVSS ) unauthenticated RCE" string.
func fatalMessage(f versionFloor, ver string) string {
	if f.cve == "" {
		// Security/transport floor without a cited CVE — fail-closed but do not
		// print misleading empty CVE/CVSS parens.
		return fmt.Sprintf(
			"%s: %s %s is below minimum v%s (security floor) — upgrade %s to >= %s",
			f.checkID, f.component, ver, f.minVer, f.component, f.minVer,
		)
	}
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
