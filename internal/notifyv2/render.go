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

package notifyv2

// RenderedNote is the string output of Render: everything the ntfy delivery
// path (internal/modules/notify) needs to compose a request. Header names
// live in the delivery module — this package produces strings only.
//
// There is deliberately no actions field: Message.Actions are typed and
// validated on the wire but dropped by this renderer until Phase 30 wires
// /approve (D-18 — no dead buttons).
type RenderedNote struct {
	Title    string
	Body     string
	Priority string
	Tags     string
	Click    string
}

// RenderOpts carries display-only enrichment the caller resolved out-of-band
// (session/window display names from the registry, click URL from dispatch).
type RenderOpts struct {
	SessionName string
	WindowName  string
	Click       string
}

// Render produces the ntfy representation of m. Pure function: no I/O, no
// logging, no mutation.
func Render(m Message, opts RenderOpts) RenderedNote {
	_ = m
	_ = opts
	return RenderedNote{} // stub — implemented in the GREEN step
}
