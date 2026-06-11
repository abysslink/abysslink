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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abysslink/abysslink/internal/secrets"
)

const (
	// caKeychainService is the keychain service holding the device SSH CA key.
	caKeychainService = "abysslink"
	// caKeychainAccount is the keychain account holding the device SSH CA key.
	caKeychainAccount = "device-ssh-ca"
	// caKeyComment labels the PEM-stored CA private key.
	caKeyComment = "abysslink-device-ssh-ca"
	// certKeyIDPrefix prefixes every minted certificate's KeyId.
	certKeyIDPrefix = "abysslink-device-"
	// certValidity is the lifetime of a minted device certificate.
	certValidity = 90 * 24 * time.Hour
	// certBackdate pads ValidAfter into the past to absorb clock skew.
	certBackdate = 5 * time.Minute
)

// caSignerLocked returns the in-process SSH CA signer, lazily loading it from
// the OS keychain or — on first ever use — generating a fresh ed25519 key and
// persisting it there. The CA private key never touches disk. Caller must
// hold s.mu (load-or-create is serialized under the Store mutex).
func (s *Store) caSignerLocked(ctx context.Context) (ssh.Signer, error) {
	if s.caSigner != nil {
		return s.caSigner, nil
	}

	pemStr, err := s.kc.Get(ctx, caKeychainService, caKeychainAccount)
	switch {
	case err == nil:
		signer, perr := ssh.ParsePrivateKey([]byte(pemStr))
		if perr != nil {
			return nil, fmt.Errorf("device: parse CA key from keychain: %w", perr)
		}
		s.caSigner = signer
		return signer, nil
	case errors.Is(err, secrets.ErrNotFound):
		// First use: fall through and create.
	default:
		return nil, fmt.Errorf("device: load CA key from keychain: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("device: generate CA key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, caKeyComment)
	if err != nil {
		return nil, fmt.Errorf("device: marshal CA key: %w", err)
	}
	if err := s.kc.Set(ctx, caKeychainService, caKeychainAccount, string(pem.EncodeToMemory(block))); err != nil {
		return nil, fmt.Errorf("device: store CA key in keychain: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("device: build CA signer: %w", err)
	}
	s.caSigner = signer
	slog.InfoContext(ctx, "device: generated new SSH CA key",
		"service", caKeychainService, "account", caKeychainAccount,
		"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}

// mintCert signs an SSH user certificate for the device public key pub:
// KeyId "abysslink-device-<name>", principals [name], ValidAfter now-5m
// (clock skew), ValidBefore now+90d, and ONLY the "permit-pty" extension —
// least privilege: the phone needs an interactive session, not forwarding or
// agent access. Returns the signed certificate and its expiry instant.
func mintCert(ca ssh.Signer, pub ssh.PublicKey, name string, serial uint64, now time.Time) (*ssh.Certificate, time.Time, error) {
	notAfter := now.Add(certValidity)
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           certKeyIDPrefix + name,
		ValidPrincipals: []string{name},
		ValidAfter:      uint64(now.Add(-certBackdate).Unix()), // #nosec G115 -- post-1970 Unix timestamps are non-negative; no int64->uint64 overflow
		ValidBefore:     uint64(notAfter.Unix()),               // #nosec G115 -- post-1970 Unix timestamps are non-negative; no int64->uint64 overflow
		Permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, time.Time{}, fmt.Errorf("device: sign certificate for %s: %w", name, err)
	}
	return cert, notAfter, nil
}

// CAPublicKey returns the CA public key as a single authorized_keys-format
// line (no trailing newline), creating the CA on first use. Callers wire it
// into sshd TrustedUserCAKeys; that wiring is outside this package.
func (s *Store) CAPublicKey(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	signer, err := s.caSignerLocked(ctx)
	if err != nil {
		return "", err
	}
	return authorizedKeyLine(signer.PublicKey()), nil
}

// authorizedKeyLine renders pub as one authorized_keys line without the
// trailing newline ssh.MarshalAuthorizedKey appends.
func authorizedKeyLine(pub ssh.PublicKey) string {
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
}

// RevokedSerials returns a copy of the SSH certificate serials invalidated by
// Rotate, Revoke, or RevokeAll, for downstream RevokedKeys/KRL wiring.
func (s *Store) RevokedSerials() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		slog.Warn("device: reload before RevokedSerials failed; serving cached state", "err", err)
	}
	return append([]uint64(nil), s.file.RevokedSerials...)
}
