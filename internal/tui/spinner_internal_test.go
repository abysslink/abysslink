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

package tui

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestSpinnerModel_AbortRecordsErr proves the finding [5] fix at the model
// level: a Ctrl-C / Ctrl-D / Esc keypress records done=true and err=ErrAborted
// and issues a quit command. Without this, RunSpinner would return nil (success)
// while the wrapped work kept running detached.
func TestSpinnerModel_AbortRecordsErr(t *testing.T) {
	for _, k := range []tea.KeyType{tea.KeyCtrlC, tea.KeyCtrlD, tea.KeyEsc} {
		m := newSpinnerModel("working", make(chan error, 1), context.Background())
		updated, cmd := m.Update(tea.KeyMsg{Type: k})
		sm, ok := updated.(spinnerModel)
		if !ok {
			t.Fatalf("key %v: Update returned %T, want spinnerModel", k, updated)
		}
		if !sm.done {
			t.Fatalf("key %v: expected done=true after abort", k)
		}
		if !errors.Is(sm.err, ErrAborted) {
			t.Fatalf("key %v: expected err=ErrAborted, got %v", k, sm.err)
		}
		if cmd == nil {
			t.Fatalf("key %v: expected a quit command, got nil", k)
		}
		if _, isQuit := cmd().(tea.QuitMsg); !isQuit {
			t.Fatalf("key %v: expected tea.QuitMsg from the returned command", k)
		}
	}
}

// TestSpinnerModel_OtherKeysDoNotAbort guards against over-eager aborting: an
// unrelated keypress must not record an abort or quit.
func TestSpinnerModel_OtherKeysDoNotAbort(t *testing.T) {
	m := newSpinnerModel("working", make(chan error, 1), context.Background())
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	sm := updated.(spinnerModel)
	if sm.done || sm.err != nil {
		t.Fatalf("unrelated key must not abort; got done=%v err=%v", sm.done, sm.err)
	}
}
