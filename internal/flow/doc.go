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

// Package flow provides composable guided wizard steps for the abysslink
// initialisation flow. Each step is a function that accepts a *FlowState and
// returns a *huh.Form (or *huh.Group) that the caller in internal/cli is
// responsible for running. No rendering logic lives here — this package holds
// only pure data (FlowState) and form-construction functions (TUI-03, D-11).
//
// Implemented in Wave 2 of Phase 35. Wave 0 test stubs in flow_test.go define
// the contract that Wave 2 must satisfy.
package flow
