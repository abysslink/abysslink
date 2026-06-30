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

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
)

// ansiEscapeRe matches ANSI CSI escape sequences (SGR: color / style codes).
// Pattern: ESC [ followed by zero or more parameter bytes (0x30–0x3f),
// zero or more intermediate bytes (0x20–0x2f), and a final byte (0x40–0x7e).
// The m suffix (SGR) is the common case; we match all final bytes to be thorough.
var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// stripANSI removes ANSI escape sequences from s, returning a plain-text string.
// Used by jsonPrinter to prevent ANSI codes from leaking into structured JSON output.
func stripANSI(s string) string {
	return ansiEscapeRe.ReplaceAllString(s, "")
}

// Printer is the sole interface through which internal/cli writes to
// stdout/stderr. Callers never use fmt.Println or os.Stdout directly.
type Printer interface {
	// Print writes a line to stdout.
	Print(msg string)
	// Printv writes key=value structured output (human: "key: value", JSON: object field).
	Printv(key, value string)
	// Error writes a line to stderr.
	Error(msg string)
	// PrintJSON encodes v as a single JSON object and writes it to stdout.
	// On jsonPrinter it emits a structured, ANSI-free record (one JSON object per line).
	// On humanPrinter it is a no-op; human output is produced through the styled Print path.
	PrintJSON(v any)
}

// humanPrinter writes plain human-readable text.
type humanPrinter struct {
	out io.Writer
	err io.Writer
}

// NewHumanPrinter returns a Printer backed by os.Stdout / os.Stderr.
func NewHumanPrinter() Printer {
	return &humanPrinter{out: os.Stdout, err: os.Stderr}
}

// NewHumanPrinterTo returns a Printer writing to custom writers (for tests).
func NewHumanPrinterTo(out, err io.Writer) Printer {
	return &humanPrinter{out: out, err: err}
}

func (p *humanPrinter) Print(msg string)         { _, _ = fmt.Fprintln(p.out, msg) }
func (p *humanPrinter) Printv(key, value string) { _, _ = fmt.Fprintf(p.out, "%s: %s\n", key, value) }
func (p *humanPrinter) Error(msg string)         { _, _ = fmt.Fprintln(p.err, msg) }

// PrintJSON is a no-op on humanPrinter. Structured data is for the JSON-mode path only.
// Human callers produce styled output via Print/Printv; they never call PrintJSON.
func (p *humanPrinter) PrintJSON(_ any) {}

// jsonPrinter emits newline-delimited JSON objects.
type jsonPrinter struct {
	out io.Writer
	err io.Writer
	enc *json.Encoder
}

// NewJSONPrinter returns a Printer that emits newline-delimited JSON.
func NewJSONPrinter() Printer {
	return newJSONPrinterTo(os.Stdout, os.Stderr)
}

// NewJSONPrinterTo returns a JSON Printer writing to custom writers (for tests).
func NewJSONPrinterTo(out, err io.Writer) Printer {
	return newJSONPrinterTo(out, err)
}

func newJSONPrinterTo(out, err io.Writer) Printer {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return &jsonPrinter{out: out, err: err, enc: enc}
}

// Print encodes msg as {"msg": "<stripped>"}, stripping any ANSI escape sequences
// before emission so that styled strings never leak colour codes into JSON consumers.
func (p *jsonPrinter) Print(msg string) {
	_ = p.enc.Encode(map[string]string{"msg": stripANSI(msg)})
}

// Printv encodes the key/value pair as a JSON object, stripping ANSI from value.
func (p *jsonPrinter) Printv(key, value string) {
	_ = p.enc.Encode(map[string]string{key: stripANSI(value)})
}

// Error writes the error message to stderr as {"error": "<msg>"}. ANSI escape
// sequences are stripped (matching Print/Printv) so a styled error string passed
// via printerError never leaks colour codes into the machine-readable channel.
func (p *jsonPrinter) Error(msg string) {
	enc := json.NewEncoder(p.err)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]string{"error": stripANSI(msg)})
}

// PrintJSON encodes v as a single JSON object (one line) using SetEscapeHTML(false).
// This is the structured data channel for commands like status/doctor/up that need
// to emit typed records (e.g. statusReport, []doctorFinding) without going through
// the styled Print path. Each call produces exactly one JSON object terminated by newline.
func (p *jsonPrinter) PrintJSON(v any) {
	_ = p.enc.Encode(v)
}
