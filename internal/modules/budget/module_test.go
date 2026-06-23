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

package budget_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/modules/budget"
)

// mockAuditWriter is a minimal AuditWriter for tests.
type mockAuditWriter struct {
	written map[string][]byte
}

func newMockAudit() *mockAuditWriter {
	return &mockAuditWriter{written: make(map[string][]byte)}
}

func (m *mockAuditWriter) WriteFile(path string, content []byte, _ os.FileMode, _ bool) error {
	if m.written == nil {
		m.written = make(map[string][]byte)
	}
	m.written[path] = content
	return nil
}

func (m *mockAuditWriter) Update(_ context.Context, path string, _ os.FileMode, content func() ([]byte, error)) error {
	b, err := content()
	if err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	if m.written == nil {
		m.written = make(map[string][]byte)
	}
	m.written[path] = b
	return nil
}

// makeCfg returns a config with the given BudgetConfig.
func makeCfg(b config.BudgetConfig) *config.Config {
	cfg := config.Defaults()
	cfg.Budget = b
	return cfg
}

// zeroCfg returns a config with a zero-value BudgetConfig (block absent from YAML).
func zeroCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Budget = config.BudgetConfig{} // zero-value: all fields zero/false
	return cfg
}

// TestBudgetModule_Detect_ZeroConfig: zero Budget block → no findings.
func TestBudgetModule_Detect_ZeroConfig(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg:   zeroCfg(),
		Audit: newMockAudit(),
	})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "zero-value Budget config must produce no findings")
}

// TestBudgetModule_Detect_LadderWarning: Ladder:true → 1 SeverityWarning finding with Check:"ladder_enabled".
func TestBudgetModule_Detect_LadderWarning(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg: makeCfg(config.BudgetConfig{
			Ladder: true,
		}),
		Audit: newMockAudit(),
	})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1, "Ladder:true should produce exactly 1 finding")
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
	assert.Equal(t, "ladder_enabled", findings[0].Check)
	assert.Equal(t, "budget", findings[0].Module)
	assert.Contains(t, findings[0].Message, "ladder")
}

// TestBudgetModule_Detect_InvalidWallClock: WallClockMinutes non-zero and < 1 → SeverityFatal finding.
// Since WallClockMinutes is int, non-zero values < 1 are negative.
func TestBudgetModule_Detect_InvalidWallClock(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg: makeCfg(config.BudgetConfig{
			WallClockMinutes: -1, // invalid: must be >= 1 if set
		}),
		Audit: newMockAudit(),
	})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings, "invalid WallClockMinutes should produce a finding")

	var fatalFindings []modules.Finding
	for _, f := range findings {
		if f.Severity == modules.SeverityFatal && f.Check == "wall_clock_minutes" {
			fatalFindings = append(fatalFindings, f)
		}
	}
	require.Len(t, fatalFindings, 1, "should have exactly 1 SeverityFatal finding for wall_clock_minutes")
	assert.Contains(t, fatalFindings[0].Message, "-1")
}

// TestBudgetModule_Detect_InvalidLoopN: LoopN set and < 2 → SeverityFatal finding.
func TestBudgetModule_Detect_InvalidLoopN(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg: makeCfg(config.BudgetConfig{
			LoopN: 1, // invalid: must be >= 2 if set
		}),
		Audit: newMockAudit(),
	})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)

	var fatal []modules.Finding
	for _, f := range findings {
		if f.Severity == modules.SeverityFatal && f.Check == "loop_n" {
			fatal = append(fatal, f)
		}
	}
	require.Len(t, fatal, 1, "LoopN=1 should produce 1 SeverityFatal finding for loop_n")
}

// TestBudgetModule_Detect_InvalidKillGrace: KillGraceSeconds out of [1,30] → SeverityFatal finding.
func TestBudgetModule_Detect_InvalidKillGrace(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg: makeCfg(config.BudgetConfig{
			KillGraceSeconds: 31, // invalid: ceiling is 30
		}),
		Audit: newMockAudit(),
	})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)

	var fatal []modules.Finding
	for _, f := range findings {
		if f.Severity == modules.SeverityFatal && f.Check == "kill_grace_seconds" {
			fatal = append(fatal, f)
		}
	}
	require.Len(t, fatal, 1, "KillGraceSeconds=31 should produce 1 SeverityFatal finding for kill_grace_seconds")
}

// TestBudgetModule_Plan_MissingBlock: zero Budget → Plan returns action to add the block.
func TestBudgetModule_Plan_MissingBlock(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg:   zeroCfg(),
		Audit: newMockAudit(),
	})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, actions, 1, "missing budget block should produce 1 action")
	assert.Equal(t, "budget", actions[0].Module)
	assert.Contains(t, actions[0].Description, "budget")
}

// TestBudgetModule_Plan_NoAction: valid non-zero Budget with no fatal findings → Plan returns empty actions.
func TestBudgetModule_Plan_NoAction(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg: makeCfg(config.BudgetConfig{
			WallClockMinutes: 30,
			LoopN:            8,
			LoopWindow:       20,
			KillGraceSeconds: 5,
			Ladder:           false,
		}),
		Audit: newMockAudit(),
	})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	// Warning findings (none expected here) do not produce actions; no fatal findings.
	assert.Empty(t, actions, "valid non-zero Budget config should produce no actions")
}

// TestBudgetModule_Apply_WritesConfig: Apply with zero Budget writes defaults to the config path via audit.
func TestBudgetModule_Apply_WritesConfig(t *testing.T) {
	t.Parallel()
	// Use a temp dir for the config path.
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "abysslink.yaml")

	mockAudit := newMockAudit()

	m := budget.NewWithConfigPath(modules.Deps{
		Cfg:   zeroCfg(),
		Audit: mockAudit,
	}, cfgFile)

	err := m.Apply(context.Background())
	require.NoError(t, err)

	// The audit writer should have received a WriteFile call.
	written, ok := mockAudit.written[cfgFile]
	require.True(t, ok, "Apply must call audit.WriteFile with the config path")
	// Content should contain budget YAML.
	assert.Contains(t, string(written), "budget:")
}

// TestBudgetModule_Verify_DelegatesToDetect: Verify re-runs Detect and returns its findings.
func TestBudgetModule_Verify_DelegatesToDetect(t *testing.T) {
	t.Parallel()
	// Ladder:true produces a warning from Detect; Verify should return the same.
	m := budget.New(modules.Deps{
		Cfg: makeCfg(config.BudgetConfig{
			Ladder: true,
		}),
		Audit: newMockAudit(),
	})
	detectFindings, err := m.Detect(context.Background())
	require.NoError(t, err)

	verifyFindings, err := m.Verify(context.Background())
	require.NoError(t, err)

	assert.Equal(t, detectFindings, verifyFindings, "Verify must return the same findings as Detect")
}

// TestBudgetModule_Name: Name returns "budget".
func TestBudgetModule_Name(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg:   zeroCfg(),
		Audit: newMockAudit(),
	})
	assert.Equal(t, "budget", m.Name())
}

// TestBudgetModule_Deps: Deps returns nil (no module dependencies).
func TestBudgetModule_Deps(t *testing.T) {
	t.Parallel()
	m := budget.New(modules.Deps{
		Cfg:   zeroCfg(),
		Audit: newMockAudit(),
	})
	assert.Nil(t, m.Deps(), "budget module has no dependencies (config-only shim)")
}

// TestBudgetModule_NoCouplingToRuntimeBudget asserts that the modules/budget package
// does not import internal/budget (the runtime watcher engine) or claudecode (D-01a).
// Uses simple source-file text inspection — mirrors the claudecode/module_test.go pattern.
// No external go/packages dependency is needed (and none is in go.mod for this project).
func TestBudgetModule_NoCouplingToRuntimeBudget(t *testing.T) {
	t.Parallel()
	// Read module.go and check for forbidden import lines.
	src, err := os.ReadFile("module.go")
	require.NoError(t, err, "must be able to read module.go")
	content := string(src)

	// Must NOT contain the runtime budget engine import (as a quoted import path).
	assert.NotContains(t, content,
		`"github.com/abysslink/abysslink/internal/budget"`,
		"modules/budget/module.go must not import internal/budget (runtime watcher engine, D-01a)")

	// Must NOT contain claudecode import.
	assert.NotContains(t, content,
		`"github.com/abysslink/abysslink/internal/modules/claudecode"`,
		"modules/budget/module.go must not import claudecode (D-01a generic constraint)")

	// Verify that internal/config IS imported (the whole point of this shim).
	assert.Contains(t, content,
		`"github.com/abysslink/abysslink/internal/config"`,
		"modules/budget/module.go must import internal/config for BudgetConfig")

	// Also check doc.go does not contain import-style references.
	docSrc, err := os.ReadFile("doc.go")
	require.NoError(t, err, "must be able to read doc.go")
	docContent := string(docSrc)

	// doc.go must not have a quoted import of the runtime budget engine.
	assert.NotContains(t, docContent,
		`"github.com/abysslink/abysslink/internal/budget"`,
		"doc.go must not import internal/budget (runtime watcher engine)")
	assert.NotContains(t, docContent,
		`"github.com/abysslink/abysslink/internal/modules/claudecode"`,
		"doc.go must not import claudecode")

	// Confirm the test file itself (this file) uses the _ = strings.Contains pattern
	// only for this documentation; the strings import is used above.
	_ = strings.TrimSpace("") // keep strings import used
}

// TestBudgetModule_SatisfiesModuleInterface is a compile-time assertion
// that budget.Module satisfies the modules.Module interface.
var _ modules.Module = (*budget.Module)(nil)
