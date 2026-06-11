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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"
)

// Bundle carries the one-time enrollment secrets returned by Enroll and
// Rotate. The caller prints or transfers it ONCE; no Store method ever
// serializes or persists a Bundle, and the Bearer and SSHPrivateKeyPEM fields
// are unrecoverable afterwards (only the bearer's SHA-256 is stored).
type Bundle struct {
	// Name is the device name the bundle was minted for.
	Name string
	// PushToken is the device's opaque push identity (also persisted in the record).
	PushToken string
	// Bearer is the bearer credential plaintext. NEVER persisted or logged.
	Bearer string
	// SSHPrivateKeyPEM is the device's ed25519 private key in OpenSSH PEM
	// format. NEVER persisted or logged.
	SSHPrivateKeyPEM string
	// SSHCertAuthorizedKey is the signed SSH user certificate as a single
	// authorized_keys-format line (what the phone installs next to its key).
	SSHCertAuthorizedKey string
	// CAPublicKeyAuthorizedKey is the CA public key as a single
	// authorized_keys-format line (for sshd TrustedUserCAKeys wiring).
	CAPublicKeyAuthorizedKey string
	// CertNotAfter is the certificate expiry instant.
	CertNotAfter time.Time
}

// minted holds one freshly minted credential set before it is committed to a
// Record and a Bundle. Never persisted.
type minted struct {
	pushToken string
	bearer    string
	bearerSHA string
	privPEM   string
	certLine  string
	caLine    string
	pubKeyFP  string
	serial    uint64
	notAfter  time.Time
}

// mintLocked mints a complete credential set for name: push token, bearer,
// ed25519 device keypair, and an SSH user certificate signed by the in-process
// CA, consuming one serial from f's monotonic counter. Caller must hold s.mu
// and commit f via saveLocked for the serial consumption to persist.
func (s *Store) mintLocked(ctx context.Context, name string, f *storeFile) (*minted, error) {
	ca, err := s.caSignerLocked(ctx)
	if err != nil {
		return nil, err
	}
	push, err := newPushToken()
	if err != nil {
		return nil, err
	}
	bearer, err := newBearer()
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("device: generate device key for %s: %w", name, err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("device: wrap device public key for %s: %w", name, err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, certKeyIDPrefix+name)
	if err != nil {
		return nil, fmt.Errorf("device: marshal device key for %s: %w", name, err)
	}

	serial := f.NextSerial
	f.NextSerial++
	cert, notAfter, err := mintCert(ca, sshPub, name, serial, s.now().UTC())
	if err != nil {
		return nil, err
	}

	return &minted{
		pushToken: push,
		bearer:    bearer,
		bearerSHA: hashBearer(bearer),
		privPEM:   string(pem.EncodeToMemory(pemBlock)),
		certLine:  authorizedKeyLine(cert),
		caLine:    authorizedKeyLine(ca.PublicKey()),
		pubKeyFP:  ssh.FingerprintSHA256(sshPub),
		serial:    serial,
		notAfter:  notAfter,
	}, nil
}

// bundle assembles the one-time Bundle for name from m.
func (m *minted) bundle(name string) *Bundle {
	return &Bundle{
		Name:                     name,
		PushToken:                m.pushToken,
		Bearer:                   m.bearer,
		SSHPrivateKeyPEM:         m.privPEM,
		SSHCertAuthorizedKey:     m.certLine,
		CAPublicKeyAuthorizedKey: m.caLine,
		CertNotAfter:             m.notAfter,
	}
}

// Enroll registers a new device under a unique name and returns its one-time
// credential Bundle. It fails with ErrExists when an active (non-revoked)
// record already holds the name — callers wanting fresh credentials for an
// existing device call Rotate. A revoked record's name may be re-enrolled;
// the new record gets a fresh ID.
func (s *Store) Enroll(ctx context.Context, name, kind string) (*Bundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateName(name); err != nil {
		return nil, err
	}
	if kind == "" {
		return nil, fmt.Errorf("device: kind must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		return nil, err
	}
	if s.findActiveLocked(name) >= 0 {
		return nil, fmt.Errorf("device: enroll %q: %w", name, ErrExists)
	}

	f := s.file.clone()
	m, err := s.mintLocked(ctx, name, &f)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	f.Devices = append(f.Devices, Record{
		ID:            newID(now),
		Name:          name,
		Kind:          kind,
		PushToken:     m.pushToken,
		BearerSHA256:  m.bearerSHA,
		SSHCertSerial: m.serial,
		SSHPubKeyFP:   m.pubKeyFP,
		CertNotAfter:  m.notAfter,
		EnrolledAt:    now,
	})
	if err := s.saveLocked(f); err != nil {
		return nil, err
	}
	slog.InfoContext(ctx, "device: enrolled",
		"name", name, "kind", kind, "id", f.Devices[len(f.Devices)-1].ID, "cert_serial", m.serial)
	return m.bundle(name), nil
}

// Rotate atomically replaces the credentials of the active device named name:
// a new push token, bearer, keypair, and certificate are minted, the old
// certificate serial is recorded in revoked_serials (DEVC-02 auditability),
// and the old bearer hash is overwritten — invalidating the old bearer the
// moment the write lands. ID and EnrolledAt are preserved; RotatedAt is set.
// Returns the new one-time Bundle.
func (s *Store) Rotate(ctx context.Context, name string) (*Bundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		return nil, err
	}
	idx := s.findActiveLocked(name)
	if idx < 0 {
		return nil, fmt.Errorf("device: rotate %q: %w", name, ErrNotFound)
	}

	f := s.file.clone()
	m, err := s.mintLocked(ctx, name, &f)
	if err != nil {
		return nil, err
	}
	r := &f.Devices[idx]
	f.RevokedSerials = append(f.RevokedSerials, r.SSHCertSerial)
	r.PushToken = m.pushToken
	r.BearerSHA256 = m.bearerSHA
	r.SSHCertSerial = m.serial
	r.SSHPubKeyFP = m.pubKeyFP
	r.CertNotAfter = m.notAfter
	r.RotatedAt = s.now().UTC()
	if err := s.saveLocked(f); err != nil {
		return nil, err
	}
	slog.InfoContext(ctx, "device: rotated credentials",
		"name", name, "id", r.ID, "cert_serial", m.serial)
	return m.bundle(name), nil
}

// revokeAt marks r revoked at instant now, blanks its push token and bearer
// hash (revocation must not leave a verifiable hash behind), and appends its
// certificate serial to f's revoked_serials.
func revokeAt(f *storeFile, r *Record, now time.Time) {
	f.RevokedSerials = append(f.RevokedSerials, r.SSHCertSerial)
	r.Revoked = true
	r.RevokedAt = now
	r.PushToken = ""
	r.BearerSHA256 = ""
}

// Revoke permanently disables the device named name. Revoking an
// already-revoked device is a no-op counted as success; an unknown name
// returns ErrNotFound.
func (s *Store) Revoke(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		return err
	}
	idx := s.findActiveLocked(name)
	if idx < 0 {
		for i := range s.file.Devices {
			if s.file.Devices[i].Name == name {
				return nil // already revoked: no-op success
			}
		}
		return fmt.Errorf("device: revoke %q: %w", name, ErrNotFound)
	}

	f := s.file.clone()
	revokeAt(&f, &f.Devices[idx], s.now().UTC())
	if err := s.saveLocked(f); err != nil {
		return err
	}
	slog.InfoContext(ctx, "device: revoked", "name", name, "id", f.Devices[idx].ID)
	return nil
}

// RevokeAll revokes every active device in ONE atomic file write (DEVC-03:
// the panic step must not be interruptible halfway). It returns the number of
// devices transitioned from active to revoked; already-revoked devices are
// no-ops counted as success and need no write.
func (s *Store) RevokeAll(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		return 0, err
	}

	f := s.file.clone()
	now := s.now().UTC()
	n := 0
	for i := range f.Devices {
		if f.Devices[i].active() {
			revokeAt(&f, &f.Devices[i], now)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	if err := s.saveLocked(f); err != nil {
		return 0, err
	}
	slog.InfoContext(ctx, "device: revoked all devices", "count", n)
	return n, nil
}
