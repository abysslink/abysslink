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

// Package flow provides composable guided setup steps as pure functions
// returning huh.Form objects. Steps thread one typed FlowState struct (no
// globals, no rendering logic). IO boundary: internal/flow must not import
// internal/cli. All form execution (RunWithContext) is the caller's
// responsibility in internal/cli.
package flow
