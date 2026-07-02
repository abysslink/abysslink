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
	"errors"
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/abysslink/abysslink/internal/ui"
)

// ErrAborted is returned by RunSpinner when the user cancels the spinner
// (Ctrl-C / Esc / Ctrl-D) before the wrapped work completed. Because Bubble Tea
// runs the terminal in raw mode, that keypress arrives as a KeyMsg — NOT a
// SIGINT — so the caller's context is never cancelled on its own. Callers MUST
// treat ErrAborted as a hard stop: the work did NOT succeed and may still be
// winding down in the background — never report success (finding [5]).
var ErrAborted = errors.New("aborted by user")

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
	ctx     context.Context //nolint:containedctx // ctx is watched by a tea.Cmd so cancellation stops the visual program (WR-02)
}

// workDoneMsg is sent when the background work goroutine completes.
type workDoneMsg struct{ err error }

// ctxDoneMsg is sent when the supplied context is cancelled, so the spinner
// program quits promptly instead of animating until work returns on its own.
type ctxDoneMsg struct{}

func newSpinnerModel(label string, result chan error, ctx context.Context) spinnerModel {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(ui.ColorAccent) // cyan accent (TUI-06)
	return spinnerModel{spinner: s, label: label, result: result, ctx: ctx}
}

func (m spinnerModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForWork(m.result), waitForCancel(m.ctx))
}

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case workDoneMsg:
		m.done = true
		m.err = msg.err
		return m, tea.Quit
	case ctxDoneMsg:
		// Context was cancelled while work is still in flight: stop the
		// visual program promptly and surface the cancellation error. work
		// itself must honour ctx to actually stop side effects (WR-02).
		m.done = true
		if m.ctx != nil && m.ctx.Err() != nil {
			m.err = m.ctx.Err()
		}
		return m, tea.Quit
	case tea.KeyMsg:
		// Make cancel intent explicit rather than relying on Bubble Tea
		// defaults (IN-04), in tandem with the WR-02 ctx wiring. Esc/Ctrl-D
		// are quit synonyms for Ctrl-C, matching LiveTable (livetable.go) so
		// the cancel keys are consistent across every interactive surface (T-023).
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyCtrlD, tea.KeyEsc:
			// Record the abort BEFORE quitting. Quitting without setting
			// done/err would leave sm.err nil, and RunSpinner would report
			// success while the work goroutine is still running detached — the
			// exact footgun in finding [5] (lock init nil-panic + silent lock,
			// enroll printing "Phone joined:" for a phone that never joined).
			m.done = true
			m.err = ErrAborted
			return m, tea.Quit
		}
		return m, nil
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

// waitForCancel returns a tea.Cmd that blocks until ctx is cancelled, then
// emits a ctxDoneMsg so the spinner stops promptly on cancellation. A nil ctx
// (defensive) yields a command that never fires.
func waitForCancel(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		if ctx == nil {
			return nil
		}
		<-ctx.Done()
		return ctxDoneMsg{}
	}
}

// RunSpinner runs work in the background.
//
//   - When animate is false (non-TTY/NO_COLOR/--json) it simply calls work and
//     returns its error — no Bubble Tea program is ever started, so this path
//     never hangs a non-interactive shell.
//   - When animate is true it runs a Bubble Tea spinner program that renders
//     until work completes or ctx is cancelled, then returns work's error (or
//     ctx.Err() if cancellation stopped the spinner first).
//
// work must honour ctx: if ctx is cancelled before work is called, RunSpinner
// returns ctx.Err() immediately. If ctx is cancelled while work is in flight,
// the visual program stops promptly (it is wired with tea.WithContext and
// watches ctx.Done()), but work keeps running until it itself observes the
// cancellation — stopping side effects is work's responsibility, not the
// spinner's.
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

	// Derive a cancellable context for the background work. On a Ctrl-C/Esc/Ctrl-D
	// abort Bubble Tea delivers a KeyMsg (raw mode) and the PARENT ctx is never
	// cancelled, so the work goroutine would otherwise keep running fully detached
	// after the user cancelled. Cancelling workCtx when the program exits gives
	// work a chance to observe the cancellation and stop its side effects — for a
	// mutation like lock init that means `tailscale lock init` can be interrupted
	// before it commits (finding [5]). Stopping side effects remains work's
	// responsibility; the spinner only signals.
	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()

	result := make(chan error, 1)
	go func() {
		result <- work(workCtx)
	}()

	m := newSpinnerModel(label, result, workCtx)
	prog := tea.NewProgram(m, tea.WithContext(ctx))
	finalModel, err := prog.Run()
	if err != nil {
		// tea.WithContext makes Run return ErrProgramKilled wrapping ctx.Err()
		// when the context is cancelled. Surface the cancellation directly
		// rather than as an opaque "spinner program" error (WR-02).
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("spinner program: %w", err)
	}
	// The program exited cleanly. Distinguish genuine work-completion from a user
	// abort: on Ctrl-C/Esc/Ctrl-D the model records ErrAborted. A model that
	// exited without EITHER a workDoneMsg or a recorded abort (done==false) is
	// also treated as an abort, so RunSpinner NEVER returns nil for work that did
	// not actually complete (finding [5]).
	if sm, ok := finalModel.(spinnerModel); ok {
		if sm.err != nil {
			return sm.err
		}
		if !sm.done {
			return ErrAborted
		}
		return nil
	}
	return ErrAborted
}
