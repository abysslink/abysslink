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

import "time"

// Record is one enrolled device as persisted in the records file. It contains
// no recoverable secret: the bearer is stored only as a SHA-256 hex digest and
// the device's SSH private key is never persisted at all.
type Record struct {
	// ID is a ULID minted at enrollment; stable across Rotate.
	ID string `json:"id"`
	// Name is the unique human-chosen device name (e.g. "phone"). Uniqueness
	// is enforced among active (non-revoked) records only, so a revoked
	// device's name can be reused by a fresh enrollment.
	Name string `json:"name"`
	// Kind is the device class; "phone" for now.
	Kind string `json:"kind"`
	// PushToken is the opaque device push identity ("ablk_p_…") consumed by
	// the Phase 29 gateway. Blanked on revocation.
	PushToken string `json:"push_token"`
	// BearerSHA256 is the lowercase-hex SHA-256 of the bearer credential.
	// The bearer plaintext is NEVER stored. Blanked on revocation so a
	// revoked record leaves no verifiable hash behind.
	BearerSHA256 string `json:"bearer_sha256"`
	// SSHCertSerial is the serial of the device's current SSH certificate,
	// drawn from the file's monotonic next_serial counter.
	SSHCertSerial uint64 `json:"ssh_cert_serial"`
	// SSHPubKeyFP is the "SHA256:…" fingerprint of the device's SSH public key.
	SSHPubKeyFP string `json:"ssh_pubkey_fp"`
	// CertNotAfter is the expiry instant of the current SSH certificate.
	CertNotAfter time.Time `json:"cert_not_after"`
	// EnrolledAt is when the device was first enrolled; stable across Rotate.
	EnrolledAt time.Time `json:"enrolled_at"`
	// RotatedAt is when the device's credentials were last rotated; zero if never.
	RotatedAt time.Time `json:"rotated_at,omitempty"`
	// LastSeen is the last fetch/ack instant reported via TouchLastSeen;
	// zero if the device has never checked in.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Revoked marks the device as permanently disabled.
	Revoked bool `json:"revoked,omitempty"`
	// RevokedAt is when the device was revoked; zero unless Revoked.
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	// TLSClientCertFP is the cert-ready (DEVC-01) slot for a future mTLS
	// client certificate fingerprint. Present in the schema now so the mTLS
	// upgrade is not a schema break; always empty in Phase 28.
	TLSClientCertFP string `json:"tls_client_cert_fp,omitempty"`
}

// active reports whether the record is usable, i.e. not revoked.
func (r *Record) active() bool { return !r.Revoked }

// staleAt reports whether the record counts as stale (DEVC-04) at instant now
// for the given inactivity window: it must be active AND either never seen and
// enrolled longer than window ago, or last seen longer than window ago.
func (r *Record) staleAt(now time.Time, window time.Duration) bool {
	if !r.active() {
		return false
	}
	cutoff := now.Add(-window)
	if r.LastSeen.IsZero() {
		return r.EnrolledAt.Before(cutoff)
	}
	return r.LastSeen.Before(cutoff)
}

// fileVersion is the records-file schema version this package reads and writes.
const fileVersion = 1

// storeFile is the top-level on-disk shape:
// {"version":1,"next_serial":N,"revoked_serials":[...],"devices":[...]}.
type storeFile struct {
	Version int `json:"version"`
	// NextSerial is the monotonic SSH certificate serial counter; the next
	// minted certificate takes this value and the counter increments.
	NextSerial uint64 `json:"next_serial"`
	// RevokedSerials accumulates the serials of every SSH certificate
	// invalidated by Rotate, Revoke, or RevokeAll (DEVC-02 auditability).
	RevokedSerials []uint64 `json:"revoked_serials,omitempty"`
	Devices        []Record `json:"devices"`
}

// newStoreFile returns an empty records file with the serial counter at 1.
func newStoreFile() storeFile {
	return storeFile{Version: fileVersion, NextSerial: 1, Devices: []Record{}}
}

// clone returns a deep copy of f. Record contains only value fields, so
// copying the slices element-wise is a full deep copy. Mutations operate on a
// clone and commit to Store memory only after the audited write succeeds, so
// a failed write never leaves memory ahead of disk.
func (f storeFile) clone() storeFile {
	c := f
	c.RevokedSerials = append([]uint64(nil), f.RevokedSerials...)
	c.Devices = append([]Record(nil), f.Devices...)
	return c
}
