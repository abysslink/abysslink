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

package attest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/shell"
)

// State is the fail-closed tri-state. The ZERO VALUE is StateWarn so a
// forgotten assignment can never read as OK.
type State int

// Tri-state values. Ordering is deliberate: the zero value is the
// indeterminate WARN.
const (
	// StateWarn is indeterminate: tool missing, EACCES, parse miss,
	// unsupported platform. Never a false OK.
	StateWarn State = iota
	// StateOK is an exact-match affirmative literal from a successful probe.
	StateOK
	// StateFail is a positively verified weakened/disabled posture.
	StateFail
)

// String returns "warn" | "ok" | "fail".
func (s State) String() string {
	switch s {
	case StateOK:
		return "ok"
	case StateFail:
		return "fail"
	default:
		return "warn"
	}
}

// Result is one probe outcome.
type Result struct {
	Probe    string // "sip" | "secureboot" | "tpm" | "platform"
	State    State
	Detail   string // human reason / remediation hint
	Evidence string // matched literal or byte summary; never secret material
}

// Prober runs local boot-state probes. LOCAL ONLY: this package must not
// import any network-capable package (enforced by TestAttestNoNetworkImports).
type Prober struct {
	Runner shell.Runner
	// EFIVarsDir is the Linux efivarfs root; a test seam. Empty means the
	// default /sys/firmware/efi/efivars.
	EFIVarsDir string
	// LookPath is a seam over shell.LookPath (used for the optional mokutil
	// corroboration probe only). Nil means shell.LookPath.
	LookPath func(string) bool
}

// New returns a Prober using r for every external command.
func New(r shell.Runner) *Prober {
	return &Prober{Runner: r, EFIVarsDir: defaultEFIVarsDir, LookPath: shell.LookPath}
}

// Summarize collapses probe results for `status`: "weakened" (any FAIL),
// "verified" (>= 1 probe, all OK), else "unverified".
func Summarize(rs []Result) string {
	if len(rs) == 0 {
		return "unverified"
	}
	allOK := true
	for _, r := range rs {
		switch r.State {
		case StateFail:
			return "weakened"
		case StateOK:
			// still a verified candidate
		default:
			allOK = false
		}
	}
	if allOK {
		return "verified"
	}
	return "unverified"
}

// localeEnv pins the child locale so literal matching cannot drift with the
// operator's locale (%m / translated strings).
func localeEnv() map[string]string {
	return map[string]string{"LC_ALL": "C", "LANG": "C"}
}

// worstState combines sub-probe states, worst wins: FAIL > WARN > OK.
func worstState(a, b State) State {
	if a == StateFail || b == StateFail {
		return StateFail
	}
	if a == StateWarn || b == StateWarn {
		return StateWarn
	}
	return StateOK
}

// downgradeOnly applies a corroboration state to cur without ever upgrading:
// the result is never better than cur (OK stays only if both say OK; a
// corroboration FAIL forces FAIL; a corroboration WARN caps an OK at WARN).
func downgradeOnly(cur, corroboration State) State {
	if corroboration == StateFail {
		return StateFail
	}
	if cur == StateOK && corroboration == StateWarn {
		return StateWarn
	}
	return cur
}

func (p *Prober) lookPath(binary string) bool {
	if p.LookPath == nil {
		return shell.LookPath(binary)
	}
	return p.LookPath(binary)
}

func (p *Prober) efiVarsDir() string {
	if p.EFIVarsDir == "" {
		return defaultEFIVarsDir
	}
	return p.EFIVarsDir
}

// ---------------------------------------------------------------------------
// Probe implementations. Untagged on purpose: they only touch shell.Runner
// and seam-controlled file paths, so the fail-closed taxonomy and the
// monotonicity property battery run on every GOOS. The build-tagged
// attest_{darwin,linux,other}.go files select which probes Collect runs.
// ---------------------------------------------------------------------------

// probeSIP runs `csrutil status` (darwin). State comes from stdout literals
// only — the exit code is never consulted (csrutil exits 0 on disabled).
func (p *Prober) probeSIP(ctx context.Context) Result {
	res, err := p.Runner.RunWithEnv(ctx, localeEnv(), "csrutil", "status")
	if err != nil {
		return Result{Probe: "sip", State: StateWarn, Detail: "csrutil unavailable — cannot determine SIP state"}
	}
	state, detail, evidence := parseCSRUtilStatus(res.Stdout)
	return Result{Probe: "sip", State: state, Detail: detail, Evidence: evidence}
}

// probeSecureBootDarwin combines `csrutil authenticated-root status` and
// `system_profiler SPiBridgeDataType -json` (JSON only — text mode has
// trailing-space drift); worst state wins. No bputil (root-only even for
// display) and no T2 nvram probe in v1 — T2 machines fall into the WARN
// taxonomy (documented limitation, no false OK).
func (p *Prober) probeSecureBootDarwin(ctx context.Context) Result {
	arState, arDetail := StateWarn, "csrutil unavailable — cannot determine Authenticated Root state"
	arEvidence := ""
	if res, err := p.Runner.RunWithEnv(ctx, localeEnv(), "csrutil", "authenticated-root", "status"); err == nil {
		arState, arDetail, arEvidence = parseAuthenticatedRoot(res.Stdout)
	}

	ibState, ibDetail := StateWarn, "system_profiler unavailable — cannot determine boot policy"
	ibEvidence := ""
	if res, err := p.Runner.RunWithEnv(ctx, localeEnv(), "system_profiler", "SPiBridgeDataType", "-json"); err == nil {
		ibState, ibDetail, ibEvidence = parseIBridgeJSON(res.Stdout)
	}

	return Result{
		Probe:    "secureboot",
		State:    worstState(arState, ibState),
		Detail:   arDetail + "; " + ibDetail,
		Evidence: strings.TrimSpace(strings.TrimPrefix(arEvidence+" | "+ibEvidence, " |")),
	}
}

// probeSecureBootLinux reads the SecureBoot/SetupMode EFI variables (a pure
// file read — no tool dependency) with the fail-closed absence taxonomy, then
// applies optional mokutil corroboration that can only DOWNGRADE the state.
func (p *Prober) probeSecureBootLinux(ctx context.Context) Result {
	r := p.efiVarState()
	// Optional corroboration: exact literals only, exit code ignored (mokutil
	// exits 0 on disabled). It can never upgrade; shim-validation-disabled
	// caps an efivar OK at WARN, a mokutil "disabled" forces FAIL.
	if p.lookPath("mokutil") {
		if res, err := p.Runner.RunWithEnv(ctx, localeEnv(), "mokutil", "--sb-state"); err == nil {
			if st, matched, ev := parseMokutilState(res.Stdout); matched {
				next := downgradeOnly(r.State, st)
				if next != r.State {
					r.Detail = fmt.Sprintf("%s; downgraded by mokutil: %s", r.Detail, ev)
				}
				r.State = next
			}
		}
	}
	return r
}

// efiVarState is the efivar half of probeSecureBootLinux: absence taxonomy,
// exact-length parse, SetupMode override. OK is reachable ONLY via
// SecureBoot==1 AND SetupMode confirmed 0 (the only affirmative path).
func (p *Prober) efiVarState() Result {
	dir := p.efiVarsDir()
	if _, err := os.Stat(filepath.Dir(dir)); err != nil {
		return Result{Probe: "secureboot", State: StateWarn, Detail: "not an EFI system (legacy BIOS) — Secure Boot state cannot be attested"}
	}
	data, err := os.ReadFile(filepath.Join(dir, efivarSecureBootName)) //nolint:gosec // G304: path is the fixed efivarfs SecureBoot variable (seam-adjustable root for tests)
	switch {
	case err != nil && os.IsNotExist(err):
		return Result{Probe: "secureboot", State: StateWarn, Detail: "firmware exposes no SecureBoot variable — Secure Boot unsupported"}
	case err != nil && os.IsPermission(err):
		return Result{Probe: "secureboot", State: StateWarn, Detail: "cannot read the SecureBoot EFI variable (permission denied) — run doctor as a user with efivarfs read access"}
	case err != nil:
		return Result{Probe: "secureboot", State: StateWarn, Detail: "cannot read the SecureBoot EFI variable: " + err.Error()}
	}
	b, perr := parseEFIVarByte(data)
	if perr != nil {
		return Result{Probe: "secureboot", State: StateWarn, Detail: "malformed SecureBoot EFI variable (unexpected length) — refusing to guess", Evidence: fmt.Sprintf("%d bytes", len(data))}
	}
	switch b {
	case 0:
		return Result{Probe: "secureboot", State: StateFail, Detail: "Secure Boot is verified DISABLED", Evidence: "SecureBoot=0"}
	case 1:
		return p.setupModeOverride()
	default:
		return Result{Probe: "secureboot", State: StateWarn, Detail: fmt.Sprintf("SecureBoot EFI variable carries unexpected value %d — refusing to guess", b), Evidence: fmt.Sprintf("SecureBoot=%d", b)}
	}
}

// setupModeOverride confirms the platform is NOT in Setup Mode before the
// SecureBoot=1 candidate becomes OK. SetupMode==1 overrides an enabled
// SecureBoot (WARN, never OK); an unreadable/malformed SetupMode is WARN too —
// only the affirmative SetupMode==0 path yields OK (monotone under deletion).
func (p *Prober) setupModeOverride() Result {
	data, err := os.ReadFile(filepath.Join(p.efiVarsDir(), efivarSetupModeName)) //nolint:gosec // G304: path is the fixed efivarfs SetupMode variable (seam-adjustable root for tests)
	if err != nil {
		return Result{Probe: "secureboot", State: StateWarn, Detail: "SecureBoot=1 but SetupMode is unreadable — cannot confirm enforcement", Evidence: "SecureBoot=1"}
	}
	sm, perr := parseEFIVarByte(data)
	if perr != nil {
		return Result{Probe: "secureboot", State: StateWarn, Detail: "SecureBoot=1 but SetupMode is malformed — cannot confirm enforcement", Evidence: "SecureBoot=1"}
	}
	switch sm {
	case 0:
		return Result{Probe: "secureboot", State: StateOK, Detail: "Secure Boot is enabled and enforcing", Evidence: "SecureBoot=1 SetupMode=0"}
	case 1:
		return Result{Probe: "secureboot", State: StateWarn, Detail: "platform is in Setup Mode — Secure Boot is not enforced despite SecureBoot=1", Evidence: "SecureBoot=1 SetupMode=1"}
	default:
		return Result{Probe: "secureboot", State: StateWarn, Detail: fmt.Sprintf("SetupMode carries unexpected value %d — cannot confirm enforcement", sm), Evidence: "SecureBoot=1"}
	}
}

// probeTPM runs tpm2_pcrread with the TCTI pinned by flag (an inherited
// TPM2TOOLS_TCTI simulator redirect is inert). Tool missing, exit 4 (no
// device / EACCES), or garbage output is WARN — this probe has no FAIL state.
func (p *Prober) probeTPM(ctx context.Context) Result {
	res, err := p.Runner.RunWithEnv(ctx, localeEnv(), "tpm2_pcrread", tpmPCRSelection, "-T", tpmTCTI)
	if err != nil {
		return Result{Probe: "tpm", State: StateWarn, Detail: "tpm2-tools unavailable — install tpm2-tools to attest TPM PCR state"}
	}
	if !res.Ok() {
		return Result{Probe: "tpm", State: StateWarn, Detail: fmt.Sprintf("tpm2_pcrread exited %d — no accessible TPM (/dev/tpmrm0 missing or unreadable; join the tss group)", res.ExitCode)}
	}
	state, detail, evidence := parsePCRRead(res.Stdout)
	return Result{Probe: "tpm", State: state, Detail: detail, Evidence: evidence}
}
