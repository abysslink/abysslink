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

package qr

import (
	"io"

	"github.com/mdp/qrterminal/v3"
)

// PrintANSI writes an ANSI-art QR code for the given payload to w.
//
// It uses HALF-BLOCK rendering (two QR modules packed into one character cell
// vertically via ▀/▄ glyphs) so the code is ~1 character per module wide and
// half as tall as the full-block form — roughly 4× smaller in area. That keeps
// small payloads (URLs, tokens) compact and lets a ~400-byte SSH key fit inside
// an 80-column terminal. Very large payloads (e.g. a full certificate line) can
// still exceed 80 columns; callers with large secrets should prefer a short
// capability URL over embedding the raw bytes. Lowest error-correction level (L)
// is used to minimise the module count.
func PrintANSI(w io.Writer, payload string) {
	config := qrterminal.Config{
		Level:          qrterminal.L,
		Writer:         w,
		HalfBlocks:     true,
		BlackChar:      qrterminal.BLACK_BLACK,
		WhiteChar:      qrterminal.WHITE_WHITE,
		BlackWhiteChar: qrterminal.BLACK_WHITE,
		WhiteBlackChar: qrterminal.WHITE_BLACK,
		QuietZone:      1,
	}
	qrterminal.GenerateWithConfig(payload, config)
}
