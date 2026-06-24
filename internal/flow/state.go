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

package flow

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/abysslink/abysslink/internal/audit"
)

// Stage index constants — ordered to match journeyLabels() (ported from
// internal/cli/journey.go:69-80).
const (
	StageAccount   = 0
	StagePrereqs   = 1
	StageConverge  = 2
	StageLock      = 3
	StageEnroll    = 4
	StageVerify    = 5
	StageACL       = 6
	StageDone      = 7
)

// flowStateFile is the filename within the state directory where the last
// completed stage is persisted. MUST match journeyStageFile in
// internal/cli/journey.go exactly — D-02 backward compatibility.
const flowStateFile = "journey-state.json" //nolint:deadcode,unused // used by callers via WriteFlowState/ReadFlowState

// flowResumeState is the on-disk JSON schema. Intentionally minimal: only an
// integer stage index; no credentials, tokens, or sensitive data ever written here.
// Schema: {"last_stage": N} — identical to journeyStageState in journey.go.
type flowResumeState struct {
	LastStage int `json:"last_stage"`
}

// FlowState carries the pure configuration data collected during the init
// wizard. It is passed by pointer through each step function (D-11: FlowState
// = pure data). SECURITY (D-12): no field may be named with "Token", "Code",
// "Secret", or "Password" — captured secrets NEVER live in FlowState. Boolean
// "Have" flags indicate that a secret was collected; the secret itself is
// handled transiently by the caller.
type FlowState struct {
	// Core identity fields.
	Email       string
	Hostname    string
	BackendType string // "tailscale" | "headscale" | "netbird"

	// Module toggles.
	EnableSSH   bool
	EnableTmux  bool
	EnableMosh  bool
	EnableNtfy  bool
	NtfyPort    int

	// Per-stage completion flags. Set to true by each step after the form is
	// accepted by the user (caller calls WriteFlowState after setting these).
	StageAccountDone  bool
	StagePrereqsDone  bool
	StageConvergeDone bool
	StageLockDone     bool
	StageEnrollDone   bool
	StageVerifyDone   bool
	StageACLDone      bool

	// HaveAuthCode is a boolean flag indicating the user went through the auth
	// code flow (D-12: the auth code itself is NEVER stored in FlowState).
	HaveAuthCode bool
}

// StageLabels returns the ordered list of stage label strings, ported from
// journeyLabels() in internal/cli/journey.go.
func StageLabels() []string {
	return []string{
		"Account",
		"Prerequisites",
		"Converge",
		"Lock",
		"Enroll",
		"Verify",
		"ACL",
		"Done",
	}
}

// WriteFlowState persists the last completed stage to stateFile.
// SECURITY: The file contains only {"last_stage": N} — no secrets, keys, or
// tokens. The write routes through internal/audit (backup + audit-log entry)
// per the CLAUDE.md mutation rule — never os.WriteFile directly. 0600 preserved.
// Ported from writeJourneyState in internal/cli/journey.go:378-391.
func WriteFlowState(stateFile string, stage int) error {
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(flowResumeState{LastStage: stage})
	if err != nil {
		return err
	}
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return err
	}
	return audit.New(logPath).WriteFile(stateFile, data, 0o600, false)
}

// ReadFlowState reads the last completed stage from stateFile.
// Returns (0, nil) when the file does not exist (first run — start from the
// beginning). Ported from readJourneyState in internal/cli/journey.go:404-418.
func ReadFlowState(stateFile string) (int, error) {
	data, err := os.ReadFile(stateFile) //nolint:gosec // G304: stateFile is a caller-supplied state path, not untrusted input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var st flowResumeState
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, err
	}
	return st.LastStage, nil
}
