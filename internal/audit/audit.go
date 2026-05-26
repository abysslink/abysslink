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

package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Entry is a single immutable audit-log record. Hash is the SHA-256 of the
// content at mutation time — the content itself is never stored here.
type Entry struct {
	Time   time.Time `json:"time"`
	Op     string    `json:"op"`
	Target string    `json:"target"`
	Hash   string    `json:"hash"` // hex-encoded SHA-256 of mutated content
	DryRun bool      `json:"dry_run"`
}

// Audit writes append-only audit-log entries and is the sole authorised path
// for any operation that records file mutations.
type Audit struct {
	logPath string
}

// New returns an Audit that appends to logPath. The file is created if it does
// not exist; intermediate directories must already exist.
func New(logPath string) *Audit {
	return &Audit{logPath: logPath}
}

// Append writes a new Entry to the audit log. content is hashed; it is never
// written to disk. If dryRun is true the entry is still logged but tagged.
func (a *Audit) Append(op, target string, content []byte, dryRun bool) error {
	sum := sha256.Sum256(content)
	entry := Entry{
		Time:   time.Now().UTC(),
		Op:     op,
		Target: target,
		Hash:   fmt.Sprintf("%x", sum),
		DryRun: dryRun,
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec
	if err != nil {
		return fmt.Errorf("audit: open log %s: %w", a.logPath, err)
	}
	defer f.Close() //nolint:errcheck

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("audit: write log: %w", err)
	}
	return nil
}

// HashOf returns the hex-encoded SHA-256 of content. Useful for callers that
// want to record a hash without appending a full entry.
func HashOf(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum)
}
