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

package approve

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// writeField writes one length-prefixed field (big-endian uint64 length, then
// the bytes) into h. Used identically in gate.go closureHash and
// audit/signed.go appendLenPrefixed. This package is a leaf — it copies the
// helper verbatim rather than calling across packages.
func writeField(h hash.Hash, field []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(field)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(field)
}

// SignApproveURL returns the HMAC-SHA256 hex signature of
// (requestID, action, closureHash) under key. Length-prefixed framing is
// consistent with audit/signed.go signBytes and gate.go writeField (D-16).
// action is either "approve" or "deny" — including it in the signed scope
// prevents cross-class reuse of a single signature.
func SignApproveURL(key []byte, requestID, action string, closureHash [32]byte) string {
	mac := hmac.New(sha256.New, key)
	writeField(mac, []byte(requestID))
	writeField(mac, []byte(action))
	_, _ = mac.Write(closureHash[:]) // fixed 32 bytes; no length prefix needed
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyApproveURL is a constant-time HMAC check over the same scope as
// SignApproveURL. It returns false (never panics) on any malformed input —
// wrong key, bad hex, truncated sig, or empty sig. It uses hmac.Equal to
// avoid a timing side-channel (never bytes.Equal).
func VerifyApproveURL(key []byte, requestID, action string, closureHash [32]byte, sigHex string) bool {
	gotBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(gotBytes) != sha256.Size {
		return false
	}
	expected := SignApproveURL(key, requestID, action, closureHash)
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(gotBytes, expectedBytes) // constant-time
}
