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

package cli_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/cli"
)

// testRecord is a typed struct for testing PrintJSON structured output.
type testRecord struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

// TestJSONPrinter_PrintJSON_StructuredOutput verifies that PrintJSON encodes a
// typed struct as a valid JSON object and the fields round-trip correctly.
func TestJSONPrinter_PrintJSON_StructuredOutput(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	rec := testRecord{Name: "abysslink", Version: "1.0.0", Status: "running"}
	p.PrintJSON(rec)

	// The output must be valid JSON.
	var decoded testRecord
	require.NoError(t, json.Unmarshal(out.Bytes(), &decoded),
		"PrintJSON output must be valid JSON")

	// All fields must survive the round-trip.
	assert.Equal(t, "abysslink", decoded.Name)
	assert.Equal(t, "1.0.0", decoded.Version)
	assert.Equal(t, "running", decoded.Status)
}

// TestJSONPrinter_PrintJSON_NoANSI verifies that PrintJSON output contains no
// ANSI escape sequences (0x1b bytes) even when the struct fields contain none.
func TestJSONPrinter_PrintJSON_NoANSI(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	rec := testRecord{Name: "abysslink", Version: "1.0.0", Status: "ok"}
	p.PrintJSON(rec)

	assert.NotContains(t, out.String(), "\x1b",
		"PrintJSON must not emit any ANSI escape sequences")
}

// TestJSONPrinter_Print_StripANSI verifies that a styled string passed to
// jsonPrinter.Print is stripped of ANSI before it reaches the JSON consumer.
func TestJSONPrinter_Print_StripANSI(t *testing.T) {
	// Produce a string that contains ANSI escape codes via lipgloss.
	styleSuccess := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	styled := styleSuccess.Render("success")

	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	p.Print(styled)

	output := out.String()
	// The JSON output must contain no ESC byte.
	assert.NotContains(t, output, "\x1b",
		"jsonPrinter.Print must strip ANSI escapes before emitting JSON")
	// The plaintext content should still be present.
	assert.Contains(t, output, "success",
		"stripped output must retain the original text content")
}

// TestJSONPrinter_Printv_StripANSI verifies that styled values passed to
// jsonPrinter.Printv are stripped of ANSI.
func TestJSONPrinter_Printv_StripANSI(t *testing.T) {
	styleMuted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styledVal := styleMuted.Render("muted-value")

	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	p.Printv("key", styledVal)

	output := out.String()
	assert.NotContains(t, output, "\x1b",
		"jsonPrinter.Printv must strip ANSI from values")
	assert.Contains(t, output, "muted-value",
		"stripped output must retain the original text content")
}

// TestHumanPrinter_PrintJSON_Noop verifies that humanPrinter.PrintJSON is a
// no-op (produces no output to stdout or stderr), as structured data is for the
// JSON-mode path only.
func TestHumanPrinter_PrintJSON_Noop(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := cli.NewHumanPrinterTo(&out, &errBuf)
	rec := testRecord{Name: "abysslink", Version: "1.0.0", Status: "ok"}
	p.PrintJSON(rec)

	assert.Empty(t, out.String(), "humanPrinter.PrintJSON must produce no output")
	assert.Empty(t, errBuf.String(), "humanPrinter.PrintJSON must produce no stderr output")
}

// TestStripANSI_PlainString verifies stripANSI is a no-op on plain strings.
// We test this indirectly via jsonPrinter.Print.
func TestStripANSI_PlainString(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	p.Print("plain text without escapes")

	output := out.String()
	assert.Contains(t, output, "plain text without escapes",
		"plain strings must be preserved intact")
	assert.NotContains(t, output, "\x1b")
}

// TestJSONPrinter_ExistingTests_StillPass is a meta-test: re-run the pre-existing
// JSON printer behaviour to confirm the human output snapshot tests still pass
// after the printer refactor.
func TestJSONPrinter_ExistingBehaviour_Print(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	// Plain string with no ANSI → msg field preserved.
	p.Print("hello")
	assert.Contains(t, out.String(), `"msg"`)
	assert.Contains(t, out.String(), `"hello"`)
}

// TestJSONPrinter_ExistingBehaviour_Printv verifies the existing Printv key/value
// shape is preserved after the refactor.
func TestJSONPrinter_ExistingBehaviour_Printv(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	p.Printv("version", "1.2.3")
	assert.Contains(t, out.String(), `"version"`)
	assert.Contains(t, out.String(), `"1.2.3"`)
}

// TestHumanPrinter_SnapshotUnchanged verifies that the human printer snapshot
// tests still pass after the printer refactor.
func TestHumanPrinter_SnapshotUnchanged(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := cli.NewHumanPrinterTo(&out, &errBuf)
	p.Print("hello")
	assert.Equal(t, "hello\n", out.String())
	assert.Empty(t, errBuf.String())

	out.Reset()
	p.Printv("status", "ok")
	assert.Equal(t, "status: ok\n", out.String())

	out.Reset()
	p.Error("boom")
	assert.Empty(t, out.String())
	assert.True(t, strings.Contains(errBuf.String(), "boom"))
}
