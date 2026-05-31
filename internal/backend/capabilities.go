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

package backend

import "errors"

// Capabilities describes what optional operations a backend supports.
// The five ROADMAP-mandated fields are Lock, AdminAPI, SSHCheck, AuthKeys,
// FunnelRejection; ACL is the lockstep-only sixth field that tracks the
// ACLManager sub-interface (RESEARCH Q6).
//
// FunnelRejection is advisory metadata only — it does NOT gate any code path;
// enforcement stays in the tailscale module Verify (RESEARCH Q5).
type Capabilities struct {
	Lock            bool // maps to Locker sub-interface
	AdminAPI        bool // maps to AdminAPI sub-interface
	SSHCheck        bool // advisory: backend enforces SSH re-authentication checks
	AuthKeys        bool // advisory: backend can mint pre-authorized auth keys
	FunnelRejection bool // advisory: backend actively rejects Funnel configuration
	ACL             bool // maps to ACLManager sub-interface (lockstep invariant)
}

// ErrUnsupported is the defense-in-depth sentinel a core Client method returns
// when a backend cannot honor it (RESEARCH:69-76). Primary guard is the
// type-assertion ok; this backstops the declarative path.
var ErrUnsupported = errors.New("backend: operation not supported by this backend")
