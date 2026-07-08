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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/abysslink/abysslink/internal/secrets"
)

const (
	keyService = "abysslink"
	keyAccount = "audit-evidence-key" // full keychain id: abysslink-audit-evidence-key
)

// KeychainStore is the minimal keychain surface the evidence signer needs.
// Satisfied by *secrets.Store (and the mock); redeclared here so tests can
// inject a fake without importing a concrete backend.
type KeychainStore interface {
	Set(ctx context.Context, service, account, secret string) error
	Get(ctx context.Context, service, account string) (string, error)
	Delete(ctx context.Context, service, account string) error
}

// loadOrCreateSigningKey returns the rig's ed25519 evidence-signing private key,
// generating and persisting a fresh one in the keychain on first use (mirroring
// the device CA pattern). The private key never touches disk. Generation is a
// keychain WRITE, so a definitively-absent key (ErrNotFound) triggers creation;
// any other keychain failure fails closed WITHOUT overwriting (a transient
// hiccup must never mint a second key that would fail to verify prior bundles).
func loadOrCreateSigningKey(ctx context.Context, kc KeychainStore) (ed25519.PrivateKey, error) {
	stored, err := kc.Get(ctx, keyService, keyAccount)
	switch {
	case err == nil:
		raw, derr := base64.StdEncoding.DecodeString(stored)
		if derr != nil {
			return nil, fmt.Errorf("evidence: decode signing key: %w", derr)
		}
		if len(raw) != ed25519.SeedSize {
			return nil, fmt.Errorf("evidence: stored signing key has wrong size %d (want %d)", len(raw), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(raw), nil
	case errors.Is(err, secrets.ErrNotFound):
		// First use: generate + store below.
	default:
		return nil, fmt.Errorf("evidence: keychain unavailable, refusing to (re)generate signing key (fail closed): %w", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, rerr := rand.Read(seed); rerr != nil {
		return nil, fmt.Errorf("evidence: generate signing key: %w", rerr)
	}
	if serr := kc.Set(ctx, keyService, keyAccount, base64.StdEncoding.EncodeToString(seed)); serr != nil {
		return nil, fmt.Errorf("evidence: store signing key: %w", serr)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// publicKeyB64 returns the base64 of an ed25519 public key (shipped in the
// manifest so a verifier needs nothing but the bundle).
func publicKeyB64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// KeyFingerprint returns the hex SHA-256 of an ed25519 public key — the value
// the operator states out-of-band and the auditor pins. Safe to print.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return fmt.Sprintf("%x", sum)
}

// SigningKeyFingerprint returns the fingerprint of the rig's evidence-signing
// key WITHOUT creating one — for a doctor readout. Returns ("", false, nil)
// when no key exists yet (absent is not an error); a real keychain failure
// propagates.
func SigningKeyFingerprint(ctx context.Context, kc KeychainStore) (string, bool, error) {
	stored, err := kc.Get(ctx, keyService, keyAccount)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("evidence: read signing key: %w", err)
	}
	raw, derr := base64.StdEncoding.DecodeString(stored)
	if derr != nil || len(raw) != ed25519.SeedSize {
		return "", false, fmt.Errorf("evidence: stored signing key is malformed")
	}
	priv := ed25519.NewKeyFromSeed(raw)
	return KeyFingerprint(priv.Public().(ed25519.PublicKey)), true, nil
}
