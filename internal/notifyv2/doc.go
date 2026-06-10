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

// Package notifyv2 defines the typed v2 notification wire schema and its pure
// ntfy renderer. Hard rule: a Message carries routing metadata ONLY — it has
// no body/content field by construction, every string field is secret-scanned
// by Validate() with no bypass path, and the package is a leaf: it imports
// nothing from internal/modules or internal/daemon (both import it instead).
package notifyv2
