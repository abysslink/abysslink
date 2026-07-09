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

package quorum

import (
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
)

// DefaultCanaryMarker is the compiled-in canary tripwire marker. It never
// appears in a legitimate action; its presence anywhere in argv is an instant
// DENY plus alert — catching both a probing attacker and a silently
// over-generalizing verifier (Thinkst canarytokens pattern). Config
// canary_paths ADD markers; no key exists to remove this one.
const DefaultCanaryMarker = "ABYSSLINK-CANARY"

// Floor rule codes. The set is compiled-in and immutable (the
// approve.CriticalPatterns idiom): no YAML field exists to remove or disable
// an entry — KnownFields(true) rejects any such key at decode time (the
// Funnel-omission pattern). doctor:sec-quorum-floor verifies the shipped
// manifest at runtime.
const (
	floorFunnelEnable        = "funnel-enable"
	floorFileVaultDisable    = "filevault-disable"
	floorLUKSErase           = "luks-erase"
	floorAuditLogDestruction = "audit-log-destruction"
	floorTailnetLockDisable  = "tailnet-lock-disable"
	floorNtfyBindAll         = "ntfy-bind-all"
	floorCanaryTripwire      = "canary-tripwire"
	// floorEvaluationError is the synthetic code emitted when the stage-0
	// evaluator itself errors or panics: the floor must be evaluable to
	// permit anything (de-energize-to-trip).
	floorEvaluationError = "floor-evaluation-error"
)

// floorMutatingBinaries is the compiled set of binaries whose path arguments
// the audit-log-destruction rule inspects.
var floorMutatingBinaries = map[string]bool{
	"rm": true, "shred": true, "truncate": true, "dd": true,
	"mv": true, "cp": true, "tee": true, "unlink": true, "srm": true,
}

// floorRule is one compiled deny-floor rule.
type floorRule struct {
	code  string
	match func(f *floor, bin string, args []string) bool
}

// floorRules is the immutable compiled rule set, evaluated in order. The
// canary tripwire is evaluated separately (it carries a marker ID).
var floorRules = []floorRule{
	{floorFunnelEnable, func(_ *floor, bin string, args []string) bool {
		return bin == "tailscale" && containsToken(args, "funnel")
	}},
	{floorFileVaultDisable, func(_ *floor, bin string, args []string) bool {
		return bin == "fdesetup" && containsToken(args, "disable")
	}},
	{floorLUKSErase, func(_ *floor, bin string, args []string) bool {
		if bin != "cryptsetup" {
			return false
		}
		for _, a := range args {
			if strings.EqualFold(a, "luksErase") || strings.EqualFold(a, "erase") {
				return true
			}
		}
		return false
	}},
	{floorAuditLogDestruction, func(f *floor, bin string, args []string) bool {
		return f.targetsAuditLog(bin, args)
	}},
	{floorTailnetLockDisable, func(_ *floor, bin string, args []string) bool {
		if bin != "tailscale" {
			return false
		}
		lockAt := -1
		for i, a := range args {
			if a == "lock" {
				lockAt = i
				break
			}
		}
		if lockAt < 0 {
			return false
		}
		for _, a := range args[lockAt+1:] {
			if a == "disable" || a == "local-disable" {
				return true
			}
		}
		return false
	}},
	{floorNtfyBindAll, func(_ *floor, bin string, args []string) bool {
		return bin == "ntfy" && ntfyBindsAllInterfaces(args)
	}},
}

// ntfyBindsAllInterfaces reports whether an ntfy invocation binds a listen
// socket to ALL interfaces. It parses the listen-flag values (and bare
// host:port arguments) instead of matching the literal "0.0.0.0" substring, so
// an empty host (":2586"), the IPv6 unspecified address ("[::]:2586",
// ":::2586"), and expanded all-zero forms are all caught — the immutable
// "ntfy binds the tailnet IP only, never all-interfaces" default.
func ntfyBindsAllInterfaces(args []string) bool {
	for i, a := range args {
		val, isListen := "", false
		switch {
		case strings.HasPrefix(a, "--listen-http="), strings.HasPrefix(a, "--listen-https="), strings.HasPrefix(a, "-L="):
			val, isListen = a[strings.IndexByte(a, '=')+1:], true
		case a == "--listen-http" || a == "--listen-https" || a == "-L":
			if i+1 < len(args) {
				val, isListen = args[i+1], true
			}
		default:
			// A bare bind-address argument looks like host:port.
			if !strings.HasPrefix(a, "-") && strings.ContainsRune(a, ':') {
				val = a
			}
		}
		if val == "" && !isListen {
			continue
		}
		if addrBindsAllInterfaces(val) {
			return true
		}
	}
	return false
}

// addrBindsAllInterfaces reports whether a listen address binds every
// interface: an empty host, 0.0.0.0, :: (IPv6 unspecified), or any all-zero
// address form. Implemented with strings only — the quorum package must never
// import net (TestQuorum_NoNetImport).
func addrBindsAllInterfaces(v string) bool {
	host := listenHost(v)
	if host == "" {
		return true
	}
	return isAllZeroHost(host)
}

// listenHost extracts the host portion of a "host:port"/"[host]:port"/"host"
// listen value.
func listenHost(v string) string {
	if strings.HasPrefix(v, "[") { // bracketed IPv6: [host] or [host]:port
		if end := strings.IndexByte(v, ']'); end >= 0 {
			return v[1:end]
		}
		return strings.TrimPrefix(v, "[")
	}
	last := strings.LastIndexByte(v, ':')
	if last < 0 {
		return v
	}
	if tail := v[last+1:]; tail != "" && isAllDigits(tail) {
		return v[:last] // strip a trailing numeric :port
	}
	return v
}

// isAllZeroHost reports whether host is composed solely of zeros and IPv4/IPv6
// separators — i.e. an unspecified/all-interfaces address (0.0.0.0, ::,
// 0:0:0:0:0:0:0:0).
func isAllZeroHost(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		if r != '0' && r != ':' && r != '.' {
			return false
		}
	}
	return true
}

// isAllDigits reports whether s is non-empty and all ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// FloorRuleCodes returns the shipped deny-floor manifest (a copy). The
// sec-quorum-floor doctor check compares this against its own compiled
// manifest so a build whose floor set drifted is a FATAL finding.
func FloorRuleCodes() []string {
	codes := make([]string, 0, len(floorRules)+1)
	for _, r := range floorRules {
		codes = append(codes, r.code)
	}
	codes = append(codes, floorCanaryTripwire)
	return codes
}

// FloorProbe is one synthetic argv that MUST evaluate to DENY with the named
// floor rule. The doctor sec-quorum-floor check evaluates every probe.
type FloorProbe struct {
	Rule string
	Name string
	Args []string
}

// FloorProbes returns one deterministic probe fixture per shipped floor rule.
// The audit-log-destruction probe targets the resolved audit log path; when
// the path cannot be resolved the probe uses a placeholder that the caller's
// engine also cannot resolve, and the doctor check reports the mismatch.
func FloorProbes() []FloorProbe {
	auditTarget := "/nonexistent/abysslink/audit.log"
	if p, err := audit.DefaultLogPath(); err == nil {
		auditTarget = p
	}
	return []FloorProbe{
		{floorFunnelEnable, "tailscale", []string{"funnel", "2586"}},
		{floorFileVaultDisable, "fdesetup", []string{"disable"}},
		{floorLUKSErase, "cryptsetup", []string{"luksErase", "/dev/sda1"}},
		{floorAuditLogDestruction, "rm", []string{"-f", auditTarget}},
		{floorTailnetLockDisable, "tailscale", []string{"lock", "disable"}},
		{floorNtfyBindAll, "ntfy", []string{"serve", "--listen-http", "0.0.0.0:2586"}},
		{floorCanaryTripwire, "cat", []string{DefaultCanaryMarker}},
	}
}

// floorHit describes a stage-0 match.
type floorHit struct {
	rule     string
	tripwire bool
	// markerLabel identifies WHICH marker fired: "default" for the compiled
	// marker, or "canary_paths[i]" for a config-added one. It is a label,
	// never the raw argv token (hygiene).
	markerLabel string
}

// floor is the stage-0 immutable deny-floor evaluator. It is constructed once
// per Engine; the only inputs beyond the compiled rule set are the resolved
// audit-log path and the ADD-ONLY canary marker list.
type floor struct {
	// auditLogPath is the resolved canonical audit-log path ("" when
	// unresolvable — the audit-log-destruction rule then falls back to a
	// path-suffix match so the floor never silently disarms).
	auditLogPath string
	// canaryMarkers is DefaultCanaryMarker plus config canary_paths (add-only).
	canaryMarkers []string
}

// newFloor builds the stage-0 evaluator. extraMarkers come from the ADD-ONLY
// quorum.canary_paths config list.
func newFloor(extraMarkers []string) *floor {
	f := &floor{canaryMarkers: append([]string{DefaultCanaryMarker}, extraMarkers...)}
	if p, err := audit.DefaultLogPath(); err == nil {
		f.auditLogPath = p
	}
	return f
}

// eval runs the compiled floor rules plus the canary tripwire over raw argv.
// It returns (hit, true) on a match. It must be wrapped by the engine's
// panic recovery: a stage-0 evaluation panic is a DENY, never a pass.
func (f *floor) eval(name string, args []string) (floorHit, bool) {
	// Evaluate the immutable rule table against every EFFECTIVE command — the
	// raw argv[0] plus any command unwrapped from a privilege/exec wrapper
	// (sudo, env, timeout, …) or lexed out of a shell interpreter -c payload —
	// so a floor-DENY action cannot be laundered through a wrapper (QG-1).
	cands, _ := normalizeCommands(name, args)
	for _, c := range cands {
		for _, r := range floorRules {
			if r.match(f, c.bin, c.args) {
				return floorHit{rule: r.code}, true
			}
		}
	}
	// Canary tripwire: any token (including the binary name) containing a marker.
	tokens := append([]string{name}, args...)
	for i, marker := range f.canaryMarkers {
		if marker == "" {
			continue
		}
		for _, tok := range tokens {
			if strings.Contains(tok, marker) {
				label := "default"
				if i > 0 {
					label = "canary_paths"
				}
				return floorHit{rule: floorCanaryTripwire, tripwire: true, markerLabel: label}, true
			}
		}
	}
	return floorHit{}, false
}

// targetsAuditLog reports whether a mutating binary's path arguments resolve
// to, under, or over the audit-log path (deleting the parent directory
// destroys the log too).
func (f *floor) targetsAuditLog(bin string, args []string) bool {
	if !floorMutatingBinaries[bin] {
		return false
	}
	for _, a := range args {
		p := strings.TrimPrefix(a, "of=") // dd write target
		if strings.HasPrefix(p, "-") || p == "" {
			continue
		}
		if f.pathHitsAuditLog(p) {
			return true
		}
	}
	return false
}

// pathHitsAuditLog compares one candidate path against the audit-log path.
func (f *floor) pathHitsAuditLog(p string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = filepath.Clean(p)
	}
	if f.auditLogPath == "" {
		// Fallback when the canonical path is unresolvable: never let the rule
		// silently disarm — match the canonical state-dir suffix instead.
		return strings.HasSuffix(abs, filepath.Join("abysslink", "audit.log"))
	}
	if abs == f.auditLogPath {
		return true
	}
	// Target is a parent of the log (rm -rf on the state dir).
	if strings.HasPrefix(f.auditLogPath, abs+string(filepath.Separator)) {
		return true
	}
	return false
}

// containsToken reports whether args contains the exact token.
func containsToken(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}
