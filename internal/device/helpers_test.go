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
	"sync"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/secrets"
)

// baseTime is the fixed test epoch every fake clock starts at.
var baseTime = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

// fakeClock is a settable clock for deterministic EnrolledAt/LastSeen/cert
// validity assertions.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: baseTime} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// fakeAudit is an in-test AuditWriter that counts writes and records perms.
// Tests are the one place allowed to call os.WriteFile directly.
type fakeAudit struct {
	mu     sync.Mutex
	writes int
	perms  []os.FileMode
}

func (f *fakeAudit) WriteFile(path string, content []byte, perm os.FileMode, _ bool) error {
	f.mu.Lock()
	f.writes++
	f.perms = append(f.perms, perm)
	f.mu.Unlock()
	if err := os.WriteFile(path, content, perm); err != nil {
		return err
	}
	// os.WriteFile only applies perm at creation; force it on rewrites too so
	// the perm-assertion test exercises what the Store requested.
	return os.Chmod(path, perm)
}

// Update mirrors the audit contract for unit tests: it calls content() to get
// the fresh bytes, then writes them through WriteFile. It holds no flock (this
// fake is for single-Store unit tests); the cross-process race tests use the
// real internal/audit writer, which takes the flock.
func (f *fakeAudit) Update(_ context.Context, path string, perm os.FileMode, content func() ([]byte, error)) error {
	data, err := content()
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	return f.WriteFile(path, data, perm, false)
}

func (f *fakeAudit) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// testStore builds a Store over a temp records file with a fake audit writer,
// a MockStore keychain, and a fake clock.
func testStore(t *testing.T) (*device.Store, *fakeAudit, *fakeClock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "devices.json")
	fa := &fakeAudit{}
	clk := newFakeClock()
	return device.New(path, fa, secrets.NewMockStore(), clk.Now), fa, clk, path
}

// bumpMtime gives path a fresh, strictly newer mtime so change detection
// fires even if two writes landed within filesystem timestamp resolution.
func bumpMtime(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	stamp := fi.ModTime().Add(10 * time.Millisecond)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}
