//go:build webui

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

package webui

// The SRI generator computes the SHA-384 of the vendored assets/htmx.min.js and
// writes sri_const_gen.go. The gen/sri tool lands in Plan 03 alongside the
// vendored htmx file; until then sri_const_gen.go carries a placeholder and
// `make check-htmx-sri` short-circuits with a NOTICE when the file is absent.
//
//go:generate go run ./gen/sri/main.go
