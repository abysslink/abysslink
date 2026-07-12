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

// Package sentinel is a deterministic, high-precision danger-signal detector
// for the exec chokepoint (P-B2 / E4.2). It flags ONE narrow host-based
// exfiltration pattern: a file-reading command that touches a known-sensitive
// path (an SSH private key, a cloud-credential file, a .env, a browser secret
// store) FOLLOWED — within a small window of execs and seconds, in that order —
// by a listed egress command opening an outbound connection to a host that is
// NOT on the benign allowlist (package registries, the tailnet, loopback).
//
// It is a GENERIC exec-pattern detector. It keys on argv/binary patterns only,
// reasons about command names and arguments only (never file contents, never
// network payloads), and names no downstream consumer — Claude Code is at most
// one opt-in consumer, never referenced here (the generic-core rule).
//
// HONEST SCOPE. This is defense-in-depth, NOT a security boundary. It catches
// the naive/opportunistic exfil and buys a signal plus a tamper-evident audit
// trail; a determined attacker evades it trivially (sharded requests, encoding/
// tunnelling, an in-process interpreter one-liner that reads-and-POSTs so no
// read command ever appears in argv, egress to a first-allowlisted host, a read
// via a tool outside the vocabulary, or an unparseable target). No learned
// model, no statistical classifier — a deterministic rule a human can read and
// predict. Precision over recall: an ambiguous case resolves to no-fire.
//
// The detector sits at the shell.Runner chokepoint as a non-invasive DECORATOR
// (Sentinel) placed INSIDE the gate, so it never touches the single-slot gate
// observer that budget.Watcher owns and never blocks, fails, or slows an exec
// (T-27-17 recover-and-continue). Every fired detection is emitted hash-only
// through internal/audit so it lands in evidence bundles for free.
package sentinel
