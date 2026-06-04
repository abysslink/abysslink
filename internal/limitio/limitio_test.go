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

package limitio

import (
	"bytes"
	"io"
	"testing"
)

// TestReadLimited_OverflowError asserts that ReadLimited returns a non-nil
// error containing "exceeded" when the reader provides more than MaxBackendBody
// bytes (N+1 sentinel / DOS-01).
func TestReadLimited_OverflowError(t *testing.T) {
	// Create a reader with MaxBackendBody+1 bytes (triggers the N+1 sentinel).
	data := bytes.Repeat([]byte("x"), int(MaxBackendBody)+1)
	r := io.NopCloser(bytes.NewReader(data))

	_, err := ReadLimited(r, MaxBackendBody)
	if err == nil {
		t.Fatal("expected ReadLimited to return an error for oversized body, got nil")
	}
	// The error message must contain "exceeded" so callers can inspect the cause.
	if !bytes.Contains([]byte(err.Error()), []byte("exceeded")) {
		t.Fatalf("expected error to contain %q, got: %q", "exceeded", err.Error())
	}
}

// TestReadLimited_ExactLimit asserts that ReadLimited succeeds (err == nil) when
// the reader provides exactly MaxBackendBody bytes and returns the full content.
func TestReadLimited_ExactLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), int(MaxBackendBody))
	r := io.NopCloser(bytes.NewReader(payload))

	got, err := ReadLimited(r, MaxBackendBody)
	if err != nil {
		t.Fatalf("expected no error for exact-limit body, got: %v", err)
	}
	if int64(len(got)) != MaxBackendBody {
		t.Fatalf("expected %d bytes, got %d", MaxBackendBody, len(got))
	}
}

// TestReadLimited_ShortRead asserts that ReadLimited succeeds and returns all
// bytes when the reader is shorter than n.
func TestReadLimited_ShortRead(t *testing.T) {
	payload := []byte("hello")
	r := io.NopCloser(bytes.NewReader(payload))

	got, err := ReadLimited(r, MaxBackendBody)
	if err != nil {
		t.Fatalf("expected no error for short read, got: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(got))
	}
}
