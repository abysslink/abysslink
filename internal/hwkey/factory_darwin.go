//go:build darwin

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

package hwkey

import (
	"fmt"

	"github.com/abysslink/abysslink/internal/shell"
)

// NewProvider returns the hardware-key provider for kind on macOS: both the
// Secure Enclave and (with configured sk-api middleware) FIDO2 are supported.
// Mirrors secrets.NewStore's per-OS factory shape.
func NewProvider(kind Kind, runner shell.Runner, opts Options) (Provider, error) {
	switch kind {
	case KindSecureEnclave:
		return newSecureEnclaveProvider(runner), nil
	case KindFIDO2:
		// darwin needs external sk-api middleware (stock Apple ssh-keygen has
		// no USB HID support); enforced inside checkAvailable.
		return newFIDO2Provider(runner, opts, true), nil
	default:
		return nil, fmt.Errorf("hwkey: unknown provider kind %q", kind)
	}
}
