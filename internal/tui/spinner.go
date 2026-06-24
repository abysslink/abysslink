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

// Package tui provides terminal user-interface components for Abysslink.
// This file implements the animated spinner model and its plain-text fallback.
package tui

import (
	"context"
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/abysslink/abysslink/internal/ui"
)

// PlainStatus returns a non-animated status line containing the label.
// Used when animation is disabled (non-TTY, NO_COLOR, --json).
func PlainStatus(label string) string {
	return "◌  " + label
}

// spinnerModel is the internal Bubble Tea model for the spinner.
type spinnerModel struct {
	spinner spinner.Model
	label   string
	done    bool
	result  chan error
	err     error
}

// workDoneMsg is sent when the background work goroutine completes.
type workDoneMsg struct{ err error }

func newSpinnerModel(label string, result chan error) spinnerModel {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(ui.ColorAccent) // cyan accent (TUI-06)
	return spinnerModel{spinner: s, label: label, result: result}
}

func (m spinnerModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForWork(m.result))
}

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case workDoneMsg:
		m.done = true
		m.err = msg.err
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	default:
		return m, nil
	}
}

func (m spinnerModel) View() string {
	if m.done {
		return ""
	}
	return fmt.Sprintf("  %s  %s\n", m.spinner.View(), m.label)
}

// waitForWork returns a tea.Cmd that blocks until the result channel receives.
func waitForWork(ch chan error) tea.Cmd {
	return func() tea.Msg {
		return workDoneMsg{err: <-ch}
	}
}

// RunSpinner runs work in the background.
//
//   - When animate is false (non-TTY/NO_COLOR/--json) it simply calls work and
//     returns its error — no Bubble Tea program is ever started, so this path
//     never hangs a non-interactive shell.
//   - When animate is true it runs a Bubble Tea spinner program that renders
//     until work completes, then returns work's error.
//
// work must honour ctx: if ctx is cancelled before work is called, RunSpinner
// returns ctx.Err() immediately.
func RunSpinner(ctx context.Context, label string, work func(context.Context) error, animate bool) error {
	// Check for early cancellation regardless of animate mode.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if !animate {
		return work(ctx)
	}

	result := make(chan error, 1)
	go func() {
		result <- work(ctx)
	}()

	m := newSpinnerModel(label, result)
	prog := tea.NewProgram(m)
	finalModel, err := prog.Run()
	if err != nil {
		return fmt.Errorf("spinner program: %w", err)
	}
	if sm, ok := finalModel.(spinnerModel); ok {
		return sm.err
	}
	return nil
}
