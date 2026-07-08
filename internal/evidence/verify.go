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

package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// VerifyResult reports an evidence-bundle verification. Valid is true only when
// the signature checks out AND every pinned content hash matches. Fingerprint
// is the signing key's fingerprint — the auditor MUST compare it to the value
// the operator stated out-of-band; a valid signature over an attacker's key is
// still "valid" internally, so the pin is the real trust anchor.
type VerifyResult struct {
	Valid       bool
	Fingerprint string
	Manifest    Manifest
	Reason      string
}

// Verify reads a `.alevidence` bundle from r and checks its internal integrity:
// the ed25519 signature over manifest.json (using the public key embedded in
// the manifest) and every pinned file SHA-256. It does NOT re-verify the audit
// HMAC chain — that attestation lives inside the signed manifest (ChainResult),
// which is the whole point of the asymmetric layer. Fails closed: any missing
// file, bad signature, or hash mismatch yields Valid=false with a reason.
func Verify(r io.Reader) (VerifyResult, error) {
	files, err := readTarGz(r)
	if err != nil {
		return VerifyResult{}, err
	}

	manifestBytes, ok := files[fileManifest]
	if !ok {
		return VerifyResult{Valid: false, Reason: "bundle is missing " + fileManifest}, nil
	}
	sigB64, ok := files[fileSignature]
	if !ok {
		return VerifyResult{Valid: false, Reason: "bundle is missing " + fileSignature}, nil
	}

	var m Manifest
	if uerr := json.Unmarshal(manifestBytes, &m); uerr != nil {
		return VerifyResult{Valid: false, Reason: "manifest is not valid JSON: " + uerr.Error()}, nil
	}

	if m.Signing.Algo != "ed25519" {
		return VerifyResult{Valid: false, Manifest: m, Reason: "unsupported signature algorithm " + m.Signing.Algo}, nil
	}
	pub, derr := base64.StdEncoding.DecodeString(m.Signing.PublicKey)
	if derr != nil || len(pub) != ed25519.PublicKeySize {
		return VerifyResult{Valid: false, Manifest: m, Reason: "manifest public key is malformed"}, nil
	}
	fp := KeyFingerprint(pub)
	// The embedded fingerprint must match the actual key (a self-consistency
	// check; the out-of-band pin is the auditor's job).
	if m.Signing.Fingerprint != fp {
		return VerifyResult{Valid: false, Manifest: m, Fingerprint: fp, Reason: "manifest fingerprint does not match its public key"}, nil
	}

	sig, serr := base64.StdEncoding.DecodeString(string(sigB64))
	if serr != nil || len(sig) != ed25519.SignatureSize {
		return VerifyResult{Valid: false, Manifest: m, Fingerprint: fp, Reason: "signature is malformed"}, nil
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		return VerifyResult{Valid: false, Manifest: m, Fingerprint: fp, Reason: "signature does not verify — manifest was altered or signed by a different key"}, nil
	}

	// Signature good → the manifest (and thus the pinned hashes) is authentic.
	// Now confirm the bundled files match those pinned hashes.
	if got := hexSHA256(files[fileAuditLog]); got != m.Contents.AuditLogSHA256 {
		return VerifyResult{Valid: false, Manifest: m, Fingerprint: fp, Reason: fmt.Sprintf("%s hash mismatch: manifest %s, bundle %s", fileAuditLog, m.Contents.AuditLogSHA256, got)}, nil
	}
	if got := hexSHA256(files[fileReport]); got != m.Contents.ReportSHA256 {
		return VerifyResult{Valid: false, Manifest: m, Fingerprint: fp, Reason: fmt.Sprintf("%s hash mismatch: manifest %s, bundle %s", fileReport, m.Contents.ReportSHA256, got)}, nil
	}

	return VerifyResult{Valid: true, Manifest: m, Fingerprint: fp}, nil
}
