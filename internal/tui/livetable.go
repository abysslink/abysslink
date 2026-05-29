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

// Package tui — live module progress table.
//
// RowEvent is a thin mirror of modules.ModuleEvent that does NOT import
// internal/modules. The CLI layer (cmd_up.go) maps ModuleEvent → RowEvent so
// that this package stays free of any modules dependency.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// RowEvent mirrors modules.ModuleEvent without importing internal/modules.
// The CLI layer is responsible for the mapping.
type RowEvent struct {
	Module   string
	Index    int    // 1-based position in the module list
	Total    int    // total number of modules
	HasError bool   // true if apply produced an error
	ErrMsg   string // first error message (if HasError)
	HasWarn  bool   // true if any warning finding was present
	WarnMsg  string // first warning message (if HasWarn)
}

// tableRowMsg is sent to the live table model when a new module event arrives.
type tableRowMsg struct{ evt RowEvent }

// tableDoneMsg is sent when no more events will arrive.
type tableDoneMsg struct{ err error }

// LiveTable is a Bubble Tea model that renders a live module progress table.
// Rows fill in as RowEvents arrive via the EventCh channel.
type LiveTable struct {
	rows    []RowEvent
	spinner spinner.Model
	done    bool
	events  chan RowEvent
	stop    chan error
}

// NewLiveTable returns a new LiveTable model. Call EventCh() to send events
// and Stop() to signal completion.
func NewLiveTable() *LiveTable {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	return &LiveTable{
		spinner: s,
		events:  make(chan RowEvent, 64),
		stop:    make(chan error, 1),
	}
}

// SendRow queues a RowEvent for the live table. Safe to call from any goroutine.
func (t *LiveTable) SendRow(evt RowEvent) {
	t.events <- evt
}

// Done signals that all events have been sent and provides the final error (if any).
func (t *LiveTable) Done(err error) {
	t.stop <- err
}

// Init implements tea.Model.
func (t *LiveTable) Init() tea.Cmd {
	return tea.Batch(t.spinner.Tick, t.listenForRow())
}

// listenForRow returns a tea.Cmd that waits for the next event or done signal.
func (t *LiveTable) listenForRow() tea.Cmd {
	return func() tea.Msg {
		select {
		case evt := <-t.events:
			return tableRowMsg{evt: evt}
		case err := <-t.stop:
			return tableDoneMsg{err: err}
		}
	}
}

// Update implements tea.Model.
func (t *LiveTable) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tableRowMsg:
		t.rows = append(t.rows, msg.evt)
		return t, tea.Batch(t.spinner.Tick, t.listenForRow())
	case tableDoneMsg:
		t.done = true
		return t, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		t.spinner, cmd = t.spinner.Update(msg)
		return t, cmd
	default:
		return t, nil
	}
}

// View implements tea.Model — renders all settled rows plus a spinner for the
// in-flight (last) row when not done.
func (t *LiveTable) View() string {
	var sb strings.Builder
	for _, row := range t.rows {
		sb.WriteString(renderRow(row))
		sb.WriteByte('\n')
	}
	if !t.done {
		sb.WriteString("  ")
		sb.WriteString(t.spinner.View())
		sb.WriteString("  scanning...\n")
	}
	return sb.String()
}

// styleSuccess/styleWarn/styleFatal/styleBold/styleMuted are local to this
// file to keep package tui self-contained. They mirror the cli package palette.
var (
	tuiSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	tuiWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD060")).Bold(true)
	tuiBold    = lipgloss.NewStyle().Bold(true)
	tuiMuted   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	tuiInfo    = lipgloss.NewStyle().Foreground(lipgloss.Color("#5C7CFA"))
)

// renderRow formats a settled RowEvent into a display line matching the
// cli.scanRowStr/applyRowStr format: icon + bold-name + status + [N/M] counter.
func renderRow(evt RowEvent) string {
	counter := tuiMuted.Render(fmt.Sprintf("[%d/%d]", evt.Index, evt.Total))
	name := tuiBold.Render(fmt.Sprintf("%-16s", evt.Module))

	var icon, status string
	switch {
	case evt.HasError:
		icon = tuiWarn.Render("⚠")
		status = tuiWarn.Render(evt.ErrMsg)
	case evt.HasWarn:
		icon = tuiWarn.Render("⚠")
		status = tuiWarn.Render(evt.WarnMsg)
	default:
		icon = tuiSuccess.Render("✓")
		status = tuiMuted.Render("done")
	}

	return "  " + counter + "  " + icon + "  " + name + "  " + status
}

// renderScanRow formats a RowEvent for the scan/plan phase.
// Uses → icon when actions are planned, ✓ when up-to-date.
func renderScanRow(evt RowEvent, hasActions bool) string {
	name := tuiBold.Render(fmt.Sprintf("%-16s", evt.Module))
	if !hasActions {
		return "  " + tuiSuccess.Render("✓") + "  " + name + "  " + tuiMuted.Render("up to date")
	}
	return "  " + tuiInfo.Render("→") + "  " + name + "  " + tuiMuted.Render("changes planned")
}

// RenderRows renders a slice of settled RowEvents as a multi-line string.
// This is the plain (non-animated) path — no Bubble Tea program is needed.
// The output includes every module name and a [N/M] counter on the last line.
func RenderRows(rows []RowEvent) string {
	if len(rows) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, row := range rows {
		sb.WriteString(renderRow(row))
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

// RenderScanRows renders a slice of settled scan-phase RowEvents.
// hasActionsMap maps module name → bool indicating changes were planned.
func RenderScanRows(rows []RowEvent, hasActionsMap map[string]bool) string {
	if len(rows) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, row := range rows {
		sb.WriteString(renderScanRow(row, hasActionsMap[row.Module]))
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

// Ensure LiveTable implements tea.Model at compile time.
var _ tea.Model = (*LiveTable)(nil)
