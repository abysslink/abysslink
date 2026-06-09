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

package secrets

import "errors"

// ErrNotFound is returned (wrapped) by KeychainStore.Get implementations when
// the requested secret genuinely does not exist in the keychain. Callers MUST
// distinguish this from every other Get failure (keychain locked, access
// denied, dbus down, platform unsupported): absence is a normal first-use
// condition, while "keychain unavailable" must fail closed.
//
// Match with errors.Is(err, secrets.ErrNotFound).
//
// COMPAT: the exact text "secret not found" is load-bearing. Legacy callers
// matched on this substring before the sentinel existed; keeping the string
// inside the sentinel preserves their behavior until they migrate to
// errors.Is. Do not reword.
var ErrNotFound = errors.New("secret not found")
