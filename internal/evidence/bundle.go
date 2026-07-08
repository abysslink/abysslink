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
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
)

// formatVersion is the bundle schema version — the contract the (future) paid
// aggregation plane consumes. Bump only for append-only-incompatible changes.
const formatVersion = 1

// Bundle file names inside the tar.gz.
const (
	fileManifest  = "manifest.json"
	fileSignature = "manifest.sig" // base64 ed25519 signature over manifest.json bytes
	fileAuditLog  = "audit.jsonl"
	fileReport    = "report.md"
)

// Manifest is the signed, human-and-machine-readable head of an evidence
// bundle. The ed25519 signature (manifest.sig) covers the exact JSON bytes of
// this struct; those bytes pin the SHA-256 of every other bundled file, so one
// signature transitively covers the whole bundle. No maps — field order must be
// deterministic so the signed bytes are reproducible.
type Manifest struct {
	FormatVersion int         `json:"alevidence_v"`
	GeneratedAt   string      `json:"generated_at"` // RFC3339 UTC
	Rig           RigIdentity `json:"rig"`
	Range         TimeRange   `json:"range"`
	Chain         ChainResult `json:"chain"`
	Contents      Contents    `json:"contents"`
	Signing       Signing     `json:"signing"`
}

// RigIdentity names the machine the evidence came from.
type RigIdentity struct {
	Hostname         string `json:"hostname"`
	AbysslinkVersion string `json:"abysslink_version"`
}

// TimeRange is the [since, until] window the bundle covers ("" = open end).
type TimeRange struct {
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
}

// ChainResult is the operator's abysslink attesting the audit-chain verification
// outcome — the part an external auditor cannot compute themselves (it needs the
// HMAC key). Signed, so the attestation is bound to the evidence key.
type ChainResult struct {
	Verified      bool   `json:"verified"` // OK && !truncation && !indeterminate
	EntryCount    int    `json:"entry_count"`
	SigsVerified  int    `json:"sigs_verified"`
	SigsSkipped   int    `json:"sigs_skipped"`
	KeyEpoch      uint32 `json:"key_epoch"`
	CounterStatus string `json:"counter_status"`
	Truncation    bool   `json:"truncation_detected"`
	Reason        string `json:"reason,omitempty"`
}

// Contents pins the SHA-256 of every other file in the bundle.
type Contents struct {
	AuditLogSHA256 string `json:"audit_jsonl_sha256"`
	ReportSHA256   string `json:"report_md_sha256"`
}

// Signing describes the ed25519 key that signed the manifest. The verifier
// checks the signature with PublicKey and the operator pins Fingerprint
// out-of-band (SSH-host-key trust model).
type Signing struct {
	Algo        string `json:"algo"` // "ed25519"
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"key_fingerprint"`
}

// CreateOptions parameterizes bundle creation.
type CreateOptions struct {
	LogPath          string
	Hostname         string
	AbysslinkVersion string
	Since            string // RFC3339 UTC, optional
	Until            string // RFC3339 UTC, optional
	Now              time.Time
}

// Create builds a signed evidence bundle from the audit log at opts.LogPath and
// writes the `.alevidence` tar.gz to out. It runs audit.Verify to attest the
// chain result, renders a human-readable report, pins content hashes in the
// manifest, and ed25519-signs the manifest with the rig's evidence key
// (lazily created on first use). Read-only w.r.t. the audit log.
func Create(ctx context.Context, kc KeychainStore, opts CreateOptions, out io.Writer) (Manifest, error) {
	akc, ok := kc.(audit.KeychainStore)
	if !ok {
		return Manifest{}, fmt.Errorf("evidence: keychain does not satisfy audit.KeychainStore")
	}

	// (1) Attest the chain (needs the HMAC key — this is the operator's vouch).
	vr, verr := audit.Verify(ctx, opts.LogPath, akc)
	if verr != nil {
		return Manifest{}, fmt.Errorf("evidence: verify audit chain: %w", verr)
	}
	epoch, eerr := audit.ReadEpochStatus(ctx, opts.LogPath, akc)
	if eerr != nil {
		return Manifest{}, fmt.Errorf("evidence: read key epoch: %w", eerr)
	}

	// (2) Raw chain bytes + a filtered, human-readable report over the window.
	entries, rerr := audit.ReadLog(opts.LogPath)
	if rerr != nil {
		return Manifest{}, fmt.Errorf("evidence: read audit log: %w", rerr)
	}
	auditJSONL, err := os.ReadFile(opts.LogPath) //nolint:gosec // app-controlled audit path
	if err != nil {
		if os.IsNotExist(err) {
			auditJSONL = nil // empty log → empty bundle, still valid
		} else {
			return Manifest{}, fmt.Errorf("evidence: read audit log file: %w", err)
		}
	}
	report := renderReport(opts, vr, epoch, entries)

	// (3) Signing key (lazy-created).
	priv, kerr := loadOrCreateSigningKey(ctx, kc)
	if kerr != nil {
		return Manifest{}, kerr
	}
	pub := priv.Public().(ed25519.PublicKey)

	m := Manifest{
		FormatVersion: formatVersion,
		GeneratedAt:   opts.Now.UTC().Format(time.RFC3339),
		Rig:           RigIdentity{Hostname: opts.Hostname, AbysslinkVersion: opts.AbysslinkVersion},
		Range:         TimeRange{Since: opts.Since, Until: opts.Until},
		Chain: ChainResult{
			Verified:      vr.OK && !vr.TruncationDetected && !vr.Indeterminate,
			EntryCount:    len(entries),
			SigsVerified:  vr.SigsVerified,
			SigsSkipped:   vr.SigsSkipped,
			KeyEpoch:      epoch.PointerEpoch,
			CounterStatus: vr.CounterStatus,
			Truncation:    vr.TruncationDetected,
			Reason:        vr.Reason,
		},
		Contents: Contents{
			AuditLogSHA256: hexSHA256(auditJSONL),
			ReportSHA256:   hexSHA256(report),
		},
		Signing: Signing{
			Algo:        "ed25519",
			PublicKey:   publicKeyB64(pub),
			Fingerprint: KeyFingerprint(pub),
		},
	}

	manifestBytes, merr := json.MarshalIndent(m, "", "  ")
	if merr != nil {
		return Manifest{}, fmt.Errorf("evidence: marshal manifest: %w", merr)
	}
	sig := ed25519.Sign(priv, manifestBytes)

	if werr := writeTarGz(out, map[string][]byte{
		fileManifest:  manifestBytes,
		fileSignature: []byte(base64.StdEncoding.EncodeToString(sig)),
		fileAuditLog:  auditJSONL,
		fileReport:    report,
	}); werr != nil {
		return Manifest{}, werr
	}
	return m, nil
}

// hexSHA256 returns the lowercase hex SHA-256 of b.
func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

// writeTarGz writes files as a gzip-compressed tar to w, in a fixed name order
// so the archive is byte-reproducible for a given input set.
func writeTarGz(w io.Writer, files map[string][]byte) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	// Fixed order — manifest + sig first so a streaming verifier can fail fast.
	for _, name := range []string{fileManifest, fileSignature, fileAuditLog, fileReport} {
		body := files[name]
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o600,
			Size:    int64(len(body)),
			ModTime: time.Unix(0, 0).UTC(), // deterministic
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("evidence: tar header %s: %w", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			return fmt.Errorf("evidence: tar write %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("evidence: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("evidence: close gzip: %w", err)
	}
	return nil
}

// readTarGz reads all bundle files into a name→bytes map (bounded to guard
// against a decompression bomb).
func readTarGz(r io.Reader) (map[string][]byte, error) {
	const maxTotal = 512 << 20 // 512 MiB across the whole bundle
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("evidence: open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	out := make(map[string][]byte, 4)
	var total int64
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return nil, fmt.Errorf("evidence: read tar: %w", terr)
		}
		total += hdr.Size
		if total > maxTotal {
			return nil, fmt.Errorf("evidence: bundle exceeds %d bytes (possible decompression bomb)", maxTotal)
		}
		body, rerr := io.ReadAll(io.LimitReader(tr, maxTotal))
		if rerr != nil {
			return nil, fmt.Errorf("evidence: read tar entry %s: %w", hdr.Name, rerr)
		}
		out[hdr.Name] = body
	}
	return out, nil
}
