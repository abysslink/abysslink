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

package device_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/secrets"
)

// TestIntegration_RealAuditWriter runs the full lifecycle through the real
// internal/audit writer: atomic 0600 writes, pre-overwrite backups, and an
// audit log that records hashes only — never bearer material.
func TestIntegration_RealAuditWriter(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	path := filepath.Join(dir, "devices.json")
	clk := newFakeClock()

	s := device.New(path, audit.New(logPath), secrets.NewMockStore(), clk.Now)

	b1, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	b2, err := s.Rotate(ctx, "phone")
	require.NoError(t, err)
	require.NoError(t, s.Revoke(ctx, "phone"))
	n, err := s.RevokeAll(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	// Records file: present, 0600, free of secret material.
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	fileBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(fileBytes), b1.Bearer)
	assert.NotContains(t, string(fileBytes), b2.Bearer)
	assert.NotContains(t, string(fileBytes), "PRIVATE KEY")

	// Audit log: every mutation recorded, no bearer material.
	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.NotEmpty(t, logBytes)
	assert.Contains(t, string(logBytes), "devices.json")
	assert.NotContains(t, string(logBytes), b1.Bearer)
	assert.NotContains(t, string(logBytes), b2.Bearer)

	// Backups: overwrites of an existing file leave .bak copies behind.
	baks, err := filepath.Glob(path + ".bak.*")
	require.NoError(t, err)
	assert.NotEmpty(t, baks, "audit writer must back up the file before overwriting")

	// State survives a fresh Store over the same file and stays consistent.
	s2 := device.New(path, audit.New(logPath), secrets.NewMockStore(), clk.Now)
	rec, ok := s2.Get("phone")
	require.True(t, ok)
	assert.True(t, rec.Revoked)
	_, ok = s2.VerifyBearer(b2.Bearer)
	assert.False(t, ok)
}
