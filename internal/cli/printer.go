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
)

// Printer is the sole interface through which internal/cli writes to
// stdout/stderr. Callers never use fmt.Println or os.Stdout directly.
type Printer interface {
	// Print writes a line to stdout.
	Print(msg string)
	// Printv writes key=value structured output (human: "key: value", JSON: object field).
	Printv(key, value string)
	// Error writes a line to stderr.
	Error(msg string)
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

func (p *jsonPrinter) Print(msg string) {
	_ = p.enc.Encode(map[string]string{"msg": msg})
}
func (p *jsonPrinter) Printv(key, value string) {
	_ = p.enc.Encode(map[string]string{key: value})
}
func (p *jsonPrinter) Error(msg string) {
	enc := json.NewEncoder(p.err)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]string{"error": msg})
}
