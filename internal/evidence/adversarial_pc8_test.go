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

package evidence_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/evidence"
	"github.com/abysslink/abysslink/internal/secrets"
)

// evidenceKeyService/Account mirror the package-internal constants in key.go —
// hardcoded here (external test package) so a test can recover the rig's signing
// key from the mock keychain to forge an internally-consistent bundle.
const (
	evidenceKeyService = "abysslink"
	evidenceKeyAccount = "audit-evidence-key"
)

// injectUnsignedTail replays the filesystem-only attack from PC8-1: with NO
// keychain access, append ONE chained-but-UNSIGNED entry whose prev_hash is a
// keyless SHA-256 of the current last raw line and whose Sig is empty. The
// keychain counter cannot be touched, so audit.Verify lands in the n<entryCount
// branch and reports CounterStatus="unknown" (injected record) while OK stays
// true.
func injectUnsignedTail(t *testing.T, logPath, target string) {
	t.Helper()
	data, err := os.ReadFile(logPath) //nolint:gosec // test fixture under the test's own temp dir
	require.NoError(t, err)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	require.NotEmpty(t, lines)
	last := lines[len(lines)-1]
	sum := sha256.Sum256(last)
	e := audit.Entry{
		Time:     time.Now().UTC(),
		Op:       "write",
		Target:   target,
		Hash:     fmt.Sprintf("%x", sha256.Sum256([]byte("attacker-content"))),
		PrevHash: hex.EncodeToString(sum[:]),
		// Sig empty (keyless link); KeyEpoch omitted (epoch 1).
	}
	line, err := json.Marshal(e)
	require.NoError(t, err)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test fixture path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	_, err = f.Write(append(line, '\n'))
	require.NoError(t, err)
}

// PC8-1 / PC8-01: the signed evidence bundle's headline Chain.Verified (and
// report.md "Verdict") must NOT coerce a tri-state "unknown" counter to PASS. An
// injected unsigned tail entry — which the CLI's audit verify treats as exit-1
// (non-clean) — must attest chain.verified=false, exactly matching the CLI.
func TestCreate_InjectedUnsignedTail_NotAttestedValid(t *testing.T) {
	logPath, kc := seededLog(t, 4)
	ctx := context.Background()

	// Baseline: a clean signed chain attests verified with a clean counter.
	var base bytes.Buffer
	bm, err := evidence.Create(ctx, kc, makeOpts(logPath), &base)
	require.NoError(t, err)
	require.True(t, bm.Chain.Verified, "clean signed chain must attest verified")
	require.Equal(t, "verified", bm.Chain.CounterStatus)

	// Filesystem-only attacker appends a chained-unsigned entry to the tail.
	injectUnsignedTail(t, logPath, "/root/.ssh/authorized_keys")

	var buf bytes.Buffer
	m, err := evidence.Create(ctx, kc, makeOpts(logPath), &buf)
	require.NoError(t, err)
	// audit.Verify flags this state CounterStatus="unknown" with an "injected
	// record" reason, but OK=true/Truncation=false/Indeterminate=false.
	assert.Equal(t, "unknown", m.Chain.CounterStatus)
	assert.Contains(t, m.Chain.Reason, "injected record")
	assert.False(t, m.Chain.Verified,
		"an injected unsigned tail entry must never attest chain.verified=true (PC8-1)")

	// The bundle is still internally intact (signature + hashes consistent), but
	// its attested verdict and report headline must both be honest.
	res, verr := evidence.Verify(bytes.NewReader(buf.Bytes()))
	require.NoError(t, verr)
	require.True(t, res.Valid, "signature+hashes remain internally consistent")
	assert.False(t, res.Manifest.Chain.Verified)
	report := extractBundleMember(t, buf.Bytes(), "report.md")
	assert.Contains(t, string(report), "**Verdict:** NOT VALID",
		"report.md headline must match the attested (not) verdict")
}

// recoverSigningKey pulls the rig's ed25519 evidence key out of the mock
// keychain so a test can re-sign an edited manifest — modelling a holder of the
// signing key (or a future-format writer), not a forgery.
func recoverSigningKey(t *testing.T, kc *secrets.MockStore) ed25519.PrivateKey {
	t.Helper()
	seedB64, err := kc.Get(context.Background(), evidenceKeyService, evidenceKeyAccount)
	require.NoError(t, err)
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

// PC8-EV-1: a VALIDLY-signed bundle whose schema version this build does not
// understand must fail closed — not be reported VALID. Re-signing keeps the
// signature/fingerprint/hashes internally consistent, so only the version gate
// can reject it (this test passes ONLY because of the format-version check).
func TestVerify_UnsupportedFormatVersion_FailsClosed(t *testing.T) {
	logPath, kc := seededLog(t, 3)
	ctx := context.Background()
	var base bytes.Buffer
	_, err := evidence.Create(ctx, kc, makeOpts(logPath), &base)
	require.NoError(t, err)
	priv := recoverSigningKey(t, kc)

	b := rewriteBundle(t, base.Bytes(), func(f map[string][]byte) {
		var m map[string]any
		require.NoError(t, json.Unmarshal(f["manifest.json"], &m))
		m["alevidence_v"] = 999999 // a schema version a v1 verifier cannot interpret
		nb, e := json.MarshalIndent(m, "", "  ")
		require.NoError(t, e)
		f["manifest.json"] = nb
		f["manifest.sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, nb)))
	})

	res, verr := evidence.Verify(bytes.NewReader(b))
	require.NoError(t, verr)
	assert.False(t, res.Valid, "an unknown format version must fail closed (PC8-EV-1)")
	assert.Contains(t, res.Reason, "unsupported bundle format version")
	assert.Equal(t, 999999, res.Manifest.FormatVersion, "the version is surfaced to the caller")
}

// tarMember is one archive entry (name + body), allowing duplicates so a test
// can model a duplicate-member bundle a map-based reader would collapse.
type tarMember struct {
	name string
	body []byte
}

func readMembers(t *testing.T, bundle []byte) []tarMember {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(bundle))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var members []tarMember
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		require.NoError(t, e)
		body, e := io.ReadAll(tr)
		require.NoError(t, e)
		members = append(members, tarMember{name: hdr.Name, body: body})
	}
	return members
}

func packMembers(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.body))}))
		_, e := tw.Write(m.body)
		require.NoError(t, e)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return out.Bytes()
}

func repackWithMembers(t *testing.T, bundle []byte, mutate func(*[]tarMember)) []byte {
	t.Helper()
	members := readMembers(t, bundle)
	mutate(&members)
	return packMembers(t, members)
}

func extractBundleMember(t *testing.T, bundle []byte, name string) []byte {
	t.Helper()
	for _, m := range readMembers(t, bundle) {
		if m.name == name {
			return m.body
		}
	}
	t.Fatalf("bundle missing member %q", name)
	return nil
}

// PC8-EV-3: a bundle carrying an extra unsigned file (unreferenced by the
// manifest) must not verify as valid — the signed manifest must transitively
// commit to the full file set.
func TestVerify_ExtraBundleMember_FailsClosed(t *testing.T) {
	b := repackWithMembers(t, mustBundle(t), func(members *[]tarMember) {
		*members = append(*members, tarMember{
			name: "README.txt",
			body: []byte("trust me, this bundle is fine\n"),
		})
	})
	res, err := evidence.Verify(bytes.NewReader(b))
	require.False(t, err == nil && res.Valid,
		"a bundle carrying an extra unsigned member must not verify as valid (PC8-EV-3)")
}

// PC8-EV-3: a duplicate member must be rejected. The attack PREPENDS a malicious
// report.md so a last-wins reader (old readTarGz) hash-checks the genuine
// trailing copy and returns Valid=true, while a first-wins extractor surfaces
// the attacker's copy. Verify must fail closed on the duplicate instead.
func TestVerify_DuplicateBundleMember_FailsClosed(t *testing.T) {
	b := repackWithMembers(t, mustBundle(t), func(members *[]tarMember) {
		// Malicious copy FIRST, genuine copy remains LAST (last-wins keeps genuine).
		shadow := tarMember{name: "report.md", body: []byte("# attacker-controlled shadow report\n")}
		*members = append([]tarMember{shadow}, *members...)
	})
	res, err := evidence.Verify(bytes.NewReader(b))
	require.False(t, err == nil && res.Valid,
		"a bundle with a duplicate member must not verify as valid (PC8-EV-3)")
}

// PC8-EV-2: Create must attest and pin ONE atomic snapshot of the audit log. The
// fix holds the same cross-process append flock a writer serializes appends
// under, for the span of its reads. This proves the lock is genuinely held:
// while a competing holder owns the append lock, Create must block rather than
// race a concurrent append between its verify/read/pin steps.
func TestCreate_HoldsAuditAppendLock(t *testing.T) {
	logPath, kc := seededLog(t, 3)
	ctx := context.Background()

	lockHeld := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		_ = audit.WithAppendLock(ctx, logPath, func() error {
			close(lockHeld)
			<-release
			return nil
		})
		close(holderDone)
	}()
	<-lockHeld // the append lock is now held by the competing holder

	createDone := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		_, err := evidence.Create(ctx, kc, makeOpts(logPath), &buf)
		createDone <- err
	}()

	select {
	case <-createDone:
		t.Fatal("evidence.Create completed while the audit append lock was held — " +
			"it does not serialize its snapshot under the flock (PC8-EV-2)")
	case <-time.After(300 * time.Millisecond):
		// Expected: Create is blocked on the append lock.
	}

	close(release) // let the holder go
	<-holderDone
	require.NoError(t, <-createDone, "Create must succeed once the lock is free")
}
