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

package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeTag(t *testing.T) {
	assert.Equal(t, "1.2.3", normalizeTag("v1.2.3"))
	assert.Equal(t, "1.2.3", normalizeTag("1.2.3"))
	assert.Equal(t, "1.2.3", normalizeTag("  v1.2.3 "))
	assert.Equal(t, normalizeTag("v1.0.0"), normalizeTag("1.0.0"))
}

func TestVerifyChecksum_Valid(t *testing.T) {
	dir := t.TempDir()
	content := []byte("fake binary content")
	sum := sha256.Sum256(content)
	hex := fmt.Sprintf("%x", sum)

	binPath := filepath.Join(dir, "abysslink")
	require.NoError(t, os.WriteFile(binPath, content, 0o600))

	checksumPath := filepath.Join(dir, "checksums.txt")
	checksumContent := fmt.Sprintf("%s  abysslink\n", hex)
	require.NoError(t, os.WriteFile(checksumPath, []byte(checksumContent), 0o600))

	err := verifyChecksum(checksumPath, "abysslink", binPath)
	assert.NoError(t, err)
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	dir := t.TempDir()
	content := []byte("real content")
	binPath := filepath.Join(dir, "abysslink")
	require.NoError(t, os.WriteFile(binPath, content, 0o600))

	checksumPath := filepath.Join(dir, "checksums.txt")
	// Wrong hash.
	require.NoError(t, os.WriteFile(checksumPath,
		[]byte("0000000000000000000000000000000000000000000000000000000000000000  abysslink\n"),
		0o600))

	err := verifyChecksum(checksumPath, "abysslink", binPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch")
}

func TestVerifyChecksum_MissingEntry(t *testing.T) {
	dir := t.TempDir()
	checksumPath := filepath.Join(dir, "checksums.txt")
	require.NoError(t, os.WriteFile(checksumPath,
		[]byte("aaaa  other_binary\n"),
		0o600))

	err := verifyChecksum(checksumPath, "abysslink", filepath.Join(dir, "abysslink"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no checksum entry")
}

func TestAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst_binary")
	src := filepath.Join(dir, "src_binary")

	require.NoError(t, os.WriteFile(dst, []byte("old"), 0o600))
	require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))

	require.NoError(t, atomicReplace(context.Background(), dst, src))

	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
}
