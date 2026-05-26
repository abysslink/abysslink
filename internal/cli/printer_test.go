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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/abysslink/abysslink/internal/cli"
)

func TestHumanPrinter_Print(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := cli.NewHumanPrinterTo(&out, &errBuf)
	p.Print("hello")
	assert.Equal(t, "hello\n", out.String())
	assert.Empty(t, errBuf.String())
}

func TestHumanPrinter_Printv(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewHumanPrinterTo(&out, &out)
	p.Printv("status", "ok")
	assert.Equal(t, "status: ok\n", out.String())
}

func TestHumanPrinter_Error(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := cli.NewHumanPrinterTo(&out, &errBuf)
	p.Error("boom")
	assert.Empty(t, out.String())
	assert.Equal(t, "boom\n", errBuf.String())
}

func TestJSONPrinter_Print(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	p.Print("hello")
	assert.Contains(t, out.String(), `"msg":"hello"`)
}

func TestJSONPrinter_Printv(t *testing.T) {
	var out bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &out)
	p.Printv("version", "1.2.3")
	assert.Contains(t, out.String(), `"version":"1.2.3"`)
}

func TestJSONPrinter_Error(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := cli.NewJSONPrinterTo(&out, &errBuf)
	p.Error("bad thing")
	assert.Empty(t, out.String())
	assert.True(t, strings.Contains(errBuf.String(), `"error"`))
	assert.Contains(t, errBuf.String(), "bad thing")
}
