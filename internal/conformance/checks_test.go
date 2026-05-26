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

package conformance_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/conformance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckNoSecretsInAuditLog_NoFile(t *testing.T) {
	ctx := context.Background()
	err := conformance.CheckNoSecretsInAuditLog(ctx, "/tmp/nonexistent-audit-log-xyzzy.log")
	assert.NoError(t, err, "missing audit log should not be an error")
}

func TestCheckNoSecretsInAuditLog_Clean(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Write a clean audit log (no secrets).
	clean := `{"time":"2026-01-01T00:00:00Z","op":"write","target":"/etc/foo","hash":"abcdef1234567890","dry_run":false}` + "\n"
	require.NoError(t, os.WriteFile(logPath, []byte(clean), 0o600))

	err := conformance.CheckNoSecretsInAuditLog(ctx, logPath)
	assert.NoError(t, err, "clean audit log should pass")
}

func TestCheckNoSecretsInAuditLog_SecretLeak(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Simulate a log entry that accidentally contains a token.
	leaky := `{"time":"2026-01-01T00:00:00Z","op":"write","target":"/etc/foo","token":"sk-ant-api03-AAABBBCCC111222333444555666777888"}` + "\n"
	require.NoError(t, os.WriteFile(logPath, []byte(leaky), 0o600))

	err := conformance.CheckNoSecretsInAuditLog(ctx, logPath)
	assert.Error(t, err, "audit log with leaked token should fail")
}

func TestCheckBinarySize_UnderLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fakebinary")
	// Write 1 byte — well under any limit.
	require.NoError(t, os.WriteFile(bin, []byte("x"), 0o600))

	err := conformance.CheckBinarySize(ctx, bin, 50<<20) // 50 MB
	assert.NoError(t, err)
}

func TestCheckBinarySize_OverLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fatbinary")
	// Write 2 bytes; set limit to 1 byte to force failure.
	require.NoError(t, os.WriteFile(bin, []byte("xx"), 0o600))

	err := conformance.CheckBinarySize(ctx, bin, 1)
	assert.Error(t, err)
}

func TestCheckBinarySize_Missing(t *testing.T) {
	ctx := context.Background()
	err := conformance.CheckBinarySize(ctx, "/tmp/no-such-binary-xyzzy", 50<<20)
	assert.Error(t, err)
}

func TestCheckNoTelemetry_CleanRepo(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	clean := `package foo

import "fmt"

func Hello() { fmt.Println("hi") }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "foo.go"), []byte(clean), 0o600))

	err := conformance.CheckNoTelemetry(ctx, dir)
	assert.NoError(t, err)
}

func TestCheckNoTelemetry_DetectsSentry(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	leaky := `package foo

import (
	"github.com/getsentry/sentry-go"
)

func track() { sentry.CaptureException(nil) }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.go"), []byte(leaky), 0o600))

	err := conformance.CheckNoTelemetry(ctx, dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "getsentry")
}
