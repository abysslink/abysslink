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

package device

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

const (
	// pushTokenPrefix marks an Abysslink device push token.
	pushTokenPrefix = "ablk_p_"
	// bearerPrefix marks an Abysslink device bearer credential.
	bearerPrefix = "ablk_b_"
	// pushTokenBytes is the entropy of a push token (128 bits).
	pushTokenBytes = 16
	// bearerBytes is the entropy of a bearer credential (256 bits).
	bearerBytes = 32
)

// randomToken returns prefix plus n bytes of crypto/rand entropy encoded as
// unpadded base64url. All credential randomness in this package flows through
// here — crypto/rand only, never math/rand.
func randomToken(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("device: read entropy: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// newPushToken mints an opaque device push identity ("ablk_p_…").
func newPushToken() (string, error) { return randomToken(pushTokenPrefix, pushTokenBytes) }

// newBearer mints a bearer credential ("ablk_b_…"). Only its SHA-256 hex
// digest is ever persisted; the plaintext lives solely in the one-time Bundle.
func newBearer() (string, error) { return randomToken(bearerPrefix, bearerBytes) }

// hashBearer returns the lowercase-hex SHA-256 of the full presented bearer
// string (prefix included). Used both when persisting at mint time and when
// hashing a presented value in VerifyBearer, so the two can never disagree.
func hashBearer(bearer string) string {
	sum := sha256.Sum256([]byte(bearer))
	return hex.EncodeToString(sum[:])
}

// newID mints a ULID device ID at instant now with explicit crypto/rand
// entropy (the internal/notifyv2 NewMsgID idiom). ulid.MustNew cannot panic
// in normal control flow: crypto/rand.Reader never errors on Go >= 1.24 and
// the timestamp overflow bound is year 10889.
func newID(now time.Time) string {
	return ulid.MustNew(ulid.Timestamp(now), rand.Reader).String()
}

// maxNameLen bounds device names; they appear in cert KeyIds and principals.
const maxNameLen = 64

// validateName enforces the device-name charset: 1..64 chars from
// [a-zA-Z0-9._-], not starting with '-' or '.'. Names become SSH certificate
// principals and KeyIds, so the charset stays conservative.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("device: name must not be empty")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("device: name %q exceeds %d characters", name, maxNameLen)
	}
	if name[0] == '-' || name[0] == '.' {
		return fmt.Errorf("device: name %q must not start with %q", name, string(name[0]))
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return fmt.Errorf("device: name %q contains invalid character %q (allowed: letters, digits, '.', '_', '-')", name, string(c))
		}
	}
	return nil
}
