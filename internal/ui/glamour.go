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

package ui

import (
	"os"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	"golang.org/x/term"
)

// markdownWrapWidth returns the column width to reflow markdown prose at:
// the terminal width, capped at 100 and defaulting to 80 when it cannot be
// determined (non-TTY / tests). glamour was previously created with
// WithWordWrap(0), which disabled wrapping entirely, so a long summary sentence
// ran off the right edge and was hard-wrapped by the terminal at an arbitrary
// column, breaking words mid-character (T-025).
func markdownWrapWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return min(100, w)
}

// ptr returns a pointer to the given string. Required because glamour's
// StyleConfig uses *string for all color and style fields (RESEARCH.md Pitfall 7).
func ptr(s string) *string { return &s }

// boolPtr returns a pointer to the given bool. Required because glamour's
// StyleConfig uses *bool for bold, underline, and similar toggle fields.
func boolPtr(b bool) *bool { return &b }

// AbyssGlamourStyle returns a glamour/ansi.StyleConfig that maps the Abyss
// brand palette to glamour's markdown rendering engine (D-14).
//
// Hex strings are sourced directly from this package's palette constants
// (single source of color, D-01):
//   - H1/H2 headings: "#22D3EE" (ColorAccent dark — cyan)
//   - Emphasis/strong: "#8B5CF6" (ColorSelection dark — violet)
//   - Code foreground: "#5C7CFA" (ColorInfo — blue)
//   - Code background: "#4B5563" (ColorDim)
//   - Body text:       "#F8F8F2" (ColorFg)
//   - Blockquote/muted:"#64748B" (ColorMuted dark — steel)
//   - Link:            "#22D3EE" (ColorAccent dark — underlined)
//
// glamour.StyleConfig uses *string/*bool fields — all values are passed
// through ptr()/boolPtr() helpers (RESEARCH.md Pitfall 7).
func AbyssGlamourStyle() ansi.StyleConfig {
	return ansi.StyleConfig{
		Document: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: ptr("#F8F8F2"),
			},
		},

		H1: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: ptr("#22D3EE"),
				Bold:  boolPtr(true),
			},
		},
		H2: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: ptr("#22D3EE"),
				Bold:  boolPtr(true),
			},
		},
		H3: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: ptr("#22D3EE"),
			},
		},
		H4: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: ptr("#22D3EE"),
			},
		},
		H5: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: ptr("#64748B"),
			},
		},
		H6: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: ptr("#64748B"),
			},
		},

		Emph: ansi.StylePrimitive{
			Color:  ptr("#8B5CF6"),
			Italic: boolPtr(true),
		},
		Strong: ansi.StylePrimitive{
			Color: ptr("#8B5CF6"),
			Bold:  boolPtr(true),
		},

		Text: ansi.StylePrimitive{
			Color: ptr("#F8F8F2"),
		},

		Link: ansi.StylePrimitive{
			Color:     ptr("#22D3EE"),
			Underline: boolPtr(true),
		},
		LinkText: ansi.StylePrimitive{
			Color: ptr("#22D3EE"),
		},

		BlockQuote: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:  ptr("#64748B"),
				Italic: boolPtr(true),
			},
		},

		Code: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:           ptr("#F8F8F2"),
				BackgroundColor: ptr("#4B5563"),
			},
		},
		CodeBlock: ansi.StyleCodeBlock{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color:           ptr("#5C7CFA"),
					BackgroundColor: ptr("#4B5563"),
				},
			},
		},
	}
}

// RenderMarkdown renders md to a terminal-safe string using the Abyss glamour
// style (D-13, D-14). The return value is always a string — this function
// never writes to stdout or any io.Writer directly (IO boundary D-07).
//
// When noColor is true (--json / NO_COLOR / non-TTY path), the plain markdown
// string is returned as-is without ANSI bytes. The caller in internal/cli
// decides the noColor value from colorEnabled() / the NO_COLOR env var.
//
// When noColor is false, glamour renders md with the AbyssGlamourStyle palette.
// If glamour returns an error the original md string is returned as a
// never-crash fallback (same pattern as renderPlain() in banner.go).
func RenderMarkdown(md string, noColor bool) string {
	if noColor {
		// Plain path: return raw markdown, no ANSI escape bytes.
		return md
	}

	r, err := glamour.NewTermRenderer(
		glamour.WithStyles(AbyssGlamourStyle()),
		glamour.WithWordWrap(markdownWrapWidth()),
	)
	if err != nil {
		// Never-crash: fall back to plain markdown on renderer creation error.
		return md
	}

	rendered, err := r.Render(md)
	if err != nil {
		// Never-crash: fall back to plain markdown on render error.
		return md
	}

	return rendered
}
