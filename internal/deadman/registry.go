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

package deadman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// statePerm is the permission mode for the armed-runs state file. 0600: the
// registry records only non-secret bookkeeping (pgid + closure hash + arm
// time), but runtime state is kept owner-only by convention (matches the audit
// log's 0600).
const statePerm = 0o600

// ArmedRun is one armed run's registry record. It carries ONLY non-secret
// bookkeeping — the process-group id, the arm-time closure hash, and the arm
// timestamp. It NEVER carries argv or environment (no secrets in the registry,
// CLAUDE.md hard rule), so a lockdown reader has exactly what it needs to find
// and disarm the process group and nothing it should not.
type ArmedRun struct {
	PGID        int       `json:"pgid"`
	ClosureHash string    `json:"closure_hash"`
	ArmedAt     time.Time `json:"armed_at"`
}

// AuditWriter is the subset of internal/audit.AuditWriter the registry needs.
// The registry mutates its state file ONLY through this interface so every
// write is recorded in the tamper-evident audit chain (T-32-19) — a forged or
// hand-edited armed-runs.json that hides an armed agent is detectable, and the
// mutation never happens via a bare os.WriteFile. Update is the cross-process
// compare-and-swap path: it holds the audit flock across the read-modify-write
// so concurrent registrars cannot lose each other's entries (T-32-22 adjacent —
// availability of an accurate registry).
type AuditWriter interface {
	Update(ctx context.Context, path string, perm os.FileMode, content func() ([]byte, error)) error
}

// Registry is the persistent, audit-written armed-run registry. A Registry
// instance is a thin handle over a state-file path + an audit writer; multiple
// instances (in the same or different processes) over the same path observe the
// same runs, because every read happens off disk and every mutation serialises
// through the audit Update lock. It is safe for concurrent use.
type Registry struct {
	statePath string
	aud       AuditWriter
}

// New returns a Registry that persists armed runs at statePath, mutating it only
// through aud (so the state file is audit-written, never a bare os.WriteFile).
// statePath is typically StatePath() (XDG_STATE_HOME/abysslink/armed-runs.json);
// tests pass a temp path + a temp audit log.
func New(statePath string, aud AuditWriter) *Registry {
	return &Registry{statePath: statePath, aud: aud}
}

// StatePath returns the canonical armed-run registry path under XDG_STATE_HOME
// (default ~/.local/state/abysslink/armed-runs.json), mirroring the daemon's
// xdgStateHome convention and audit.DefaultLogPath. It does NOT create the file
// (Register creates it via the audit writer), but it ensures the parent
// directory exists so the first audit write can land.
func StatePath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("deadman: home dir: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "abysslink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("deadman: mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "armed-runs.json"), nil
}

// Register adds run to the registry. It performs a cross-process
// read-modify-write through the audit Update lock so two registrars cannot lose
// each other's entries, and the mutation is recorded in the audit chain. A run
// with a pgid already present is replaced (re-arm of the same group updates the
// closure hash + timestamp) rather than duplicated.
func (r *Registry) Register(run ArmedRun) error {
	return r.aud.Update(context.Background(), r.statePath, statePerm, func() ([]byte, error) {
		runs, err := readRuns(r.statePath)
		if err != nil {
			return nil, err
		}
		out := make([]ArmedRun, 0, len(runs)+1)
		for _, existing := range runs {
			if existing.PGID != run.PGID {
				out = append(out, existing)
			}
		}
		out = append(out, run)
		return marshalRuns(out)
	})
}

// Deregister removes the run with the given pgid. Deregistering a pgid that is
// not present is a no-op (returns nil) — a clean exit that races a never-started
// registration must not error. When the pgid is absent the content func returns
// (nil, nil) so Update writes nothing (no spurious audit entry, no backup).
func (r *Registry) Deregister(pgid int) error {
	return r.aud.Update(context.Background(), r.statePath, statePerm, func() ([]byte, error) {
		runs, err := readRuns(r.statePath)
		if err != nil {
			return nil, err
		}
		out := make([]ArmedRun, 0, len(runs))
		found := false
		for _, existing := range runs {
			if existing.PGID == pgid {
				found = true
				continue
			}
			out = append(out, existing)
		}
		if !found {
			return nil, nil // no change — Update records and writes nothing
		}
		return marshalRuns(out)
	})
}

// List returns every registered armed run. A missing state file (no arm has
// ever registered) yields an empty slice, not an error. List NEVER signals any
// process — it is a pure read; pgid liveness/pruning is the caller's concern
// (Lockdown), not List's.
func (r *Registry) List() ([]ArmedRun, error) {
	return readRuns(r.statePath)
}

// ListLive returns the registered runs whose process group is still alive,
// pruning entries whose pgid no longer exists (a process that died without
// deregistering). Pruning is bookkeeping ONLY — ListLive never signals a live
// process; it uses signal 0 (the null signal) purely to probe existence. The
// returned slice is the live subset; the on-disk file is NOT rewritten here
// (callers that want to persist the prune deregister explicitly).
func (r *Registry) ListLive() ([]ArmedRun, error) {
	runs, err := readRuns(r.statePath)
	if err != nil {
		return nil, err
	}
	live := make([]ArmedRun, 0, len(runs))
	for _, run := range runs {
		if run.PGID <= 0 {
			continue // never probe a non-positive pgid (Pitfall 3 hygiene)
		}
		// Signal 0 to the process group is a liveness probe: it performs error
		// checking but sends no signal. ESRCH => the group is gone.
		if err := syscall.Kill(-run.PGID, 0); err != nil && errors.Is(err, syscall.ESRCH) {
			continue
		}
		live = append(live, run)
	}
	return live, nil
}

// readRuns reads and unmarshals the state file. A missing file is an empty
// registry (not an error). It uses os.ReadFile for the READ only — every WRITE
// goes through the audit writer (Register/Deregister via aud.Update).
func readRuns(statePath string) ([]ArmedRun, error) {
	raw, err := os.ReadFile(statePath) //nolint:gosec // G304: statePath is the internal registry path (StatePath/test temp), not user-controlled
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("deadman: read registry %s: %w", statePath, err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var runs []ArmedRun
	if err := json.Unmarshal(raw, &runs); err != nil {
		return nil, fmt.Errorf("deadman: parse registry %s: %w", statePath, err)
	}
	return runs, nil
}

// marshalRuns serialises runs to indented JSON for the state file.
func marshalRuns(runs []ArmedRun) ([]byte, error) {
	data, err := json.MarshalIndent(runs, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("deadman: marshal registry: %w", err)
	}
	return data, nil
}
