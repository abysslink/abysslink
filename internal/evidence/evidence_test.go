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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/evidence"
	"github.com/abysslink/abysslink/internal/secrets"
)

// seededLog writes a small signed audit chain and returns its path + keychain.
func seededLog(t *testing.T, nEntries int) (string, *secrets.MockStore) {
	t.Helper()
	kc := secrets.NewMockStore()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	ctx := context.Background()
	for i := 0; i < nEntries; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("content-%d", i)))
		require.NoError(t, sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: sum},
			fmt.Sprintf("/tmp/target-%d", i), false))
	}
	return logPath, kc
}

func makeOpts(logPath string) evidence.CreateOptions {
	return evidence.CreateOptions{
		LogPath:          logPath,
		Hostname:         "rig-test",
		AbysslinkVersion: "v4.0.1",
		Now:              time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
}

func TestCreateVerify_RoundTrip(t *testing.T) {
	logPath, kc := seededLog(t, 5)
	var buf bytes.Buffer
	m, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &buf)
	require.NoError(t, err)
	assert.Equal(t, 1, m.FormatVersion)
	assert.True(t, m.Chain.Verified, "a clean signed chain must attest verified")
	assert.Equal(t, 5, m.Chain.EntryCount)
	assert.Equal(t, 5, m.Chain.SigsVerified)
	assert.NotEmpty(t, m.Signing.Fingerprint)

	res, verr := evidence.Verify(bytes.NewReader(buf.Bytes()))
	require.NoError(t, verr)
	assert.True(t, res.Valid, "reason: %s", res.Reason)
	assert.Equal(t, m.Signing.Fingerprint, res.Fingerprint)
	assert.Equal(t, 5, res.Manifest.Chain.EntryCount)
}

func TestCreate_StableFingerprintAcrossBundles(t *testing.T) {
	// The signing key is persisted, so two bundles from the same rig share a
	// fingerprint — the value an auditor pins once.
	logPath, kc := seededLog(t, 2)
	var b1, b2 bytes.Buffer
	m1, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &b1)
	require.NoError(t, err)
	m2, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &b2)
	require.NoError(t, err)
	assert.Equal(t, m1.Signing.Fingerprint, m2.Signing.Fingerprint)
}

func TestVerify_EmptyLog(t *testing.T) {
	// No audit log yet (fresh install): the bundle is still well-formed and
	// verifies; the chain attests 0 entries.
	kc := secrets.NewMockStore()
	logPath := filepath.Join(t.TempDir(), "audit.log") // never created
	var buf bytes.Buffer
	m, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &buf)
	require.NoError(t, err)
	assert.Equal(t, 0, m.Chain.EntryCount)
	res, verr := evidence.Verify(bytes.NewReader(buf.Bytes()))
	require.NoError(t, verr)
	assert.True(t, res.Valid, "reason: %s", res.Reason)
}

// --- Tamper battery: every mutation must flip Valid to false. ---

// rewriteBundle unpacks a bundle, lets fn mutate the name→bytes map, and
// repacks it as tar.gz (preserving the manifest+sig order).
func rewriteBundle(t *testing.T, in []byte, fn func(files map[string][]byte)) []byte {
	t.Helper()
	files := map[string][]byte{}
	gz, err := gzip.NewReader(bytes.NewReader(in))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var order []string
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		require.NoError(t, e)
		body, e := io.ReadAll(tr)
		require.NoError(t, e)
		files[hdr.Name] = body
		order = append(order, hdr.Name)
	}
	fn(files)
	var out bytes.Buffer
	ngz := gzip.NewWriter(&out)
	tw := tar.NewWriter(ngz)
	for _, name := range order {
		body, present := files[name]
		if !present {
			continue // fn deleted it — genuinely omit from the repacked bundle
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}))
		_, e := tw.Write(body)
		require.NoError(t, e)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, ngz.Close())
	return out.Bytes()
}

func mustBundle(t *testing.T) []byte {
	t.Helper()
	logPath, kc := seededLog(t, 3)
	var buf bytes.Buffer
	_, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &buf)
	require.NoError(t, err)
	return buf.Bytes()
}

func TestVerify_TamperedAuditLog(t *testing.T) {
	b := rewriteBundle(t, mustBundle(t), func(f map[string][]byte) {
		f["audit.jsonl"] = append(f["audit.jsonl"], []byte("{\"op\":\"forged\"}\n")...)
	})
	res, err := evidence.Verify(bytes.NewReader(b))
	require.NoError(t, err)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "audit.jsonl hash mismatch")
}

func TestVerify_TamperedReport(t *testing.T) {
	b := rewriteBundle(t, mustBundle(t), func(f map[string][]byte) {
		f["report.md"] = []byte("# totally different report\n")
	})
	res, err := evidence.Verify(bytes.NewReader(b))
	require.NoError(t, err)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "report.md hash mismatch")
}

func TestVerify_TamperedManifestBreaksSignature(t *testing.T) {
	b := rewriteBundle(t, mustBundle(t), func(f map[string][]byte) {
		var m map[string]any
		require.NoError(t, json.Unmarshal(f["manifest.json"], &m))
		m["generated_at"] = "2000-01-01T00:00:00Z" // any change
		nb, _ := json.MarshalIndent(m, "", "  ")
		f["manifest.json"] = nb
	})
	res, err := evidence.Verify(bytes.NewReader(b))
	require.NoError(t, err)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "signature does not verify")
}

func TestVerify_SwappedKeyIsSelfConsistentButFingerprintChanges(t *testing.T) {
	// An attacker re-signs a rewritten manifest with THEIR key and updates the
	// embedded pubkey+fingerprint to match: the bundle is now internally valid,
	// but the fingerprint differs from the operator's pinned one — which is
	// exactly why verify-evidence surfaces the fingerprint for out-of-band
	// comparison. This test documents that trust boundary.
	orig := mustBundle(t)
	res, err := evidence.Verify(bytes.NewReader(orig))
	require.NoError(t, err)
	require.True(t, res.Valid)
	genuineFP := res.Fingerprint

	// A different rig (different persisted key) → different fingerprint.
	logPath2, kc2 := seededLog(t, 3)
	var buf2 bytes.Buffer
	_, err = evidence.Create(context.Background(), kc2, makeOpts(logPath2), &buf2)
	require.NoError(t, err)
	res2, err := evidence.Verify(bytes.NewReader(buf2.Bytes()))
	require.NoError(t, err)
	require.True(t, res2.Valid)
	assert.NotEqual(t, genuineFP, res2.Fingerprint,
		"a bundle signed by a different key must present a different fingerprint")
}

func TestVerify_MissingSignature(t *testing.T) {
	b := rewriteBundle(t, mustBundle(t), func(f map[string][]byte) {
		delete(f, "manifest.sig")
	})
	res, err := evidence.Verify(bytes.NewReader(b))
	require.NoError(t, err)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "missing")
}

func TestVerify_NotAGzip(t *testing.T) {
	_, err := evidence.Verify(bytes.NewReader([]byte("not a gzip at all")))
	require.Error(t, err)
}
