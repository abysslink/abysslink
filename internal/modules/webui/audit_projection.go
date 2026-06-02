//go:build webui

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

package webui

import (
	"github.com/abysslink/abysslink/internal/audit"
)

// auditTimeLayout is the timestamp format rendered in the audit timeline. It is
// UTC with second precision — no nanoseconds (UI-SPEC View 3).
const auditTimeLayout = "2006-01-02 15:04:05"

// AuditEntryView is the ONLY struct the audit templates may render. It exposes
// exactly the four metadata fields permitted by WEB-07 / AUD-04 — time, op,
// target, and dry-run — and deliberately omits Hash, PrevHash, Sig, and any
// body/content/data field. Because the template receives []AuditEntryView and
// never the raw audit.Entry, accidental exposure of the tamper-evident chain is
// architecturally impossible (T-19-07).
type AuditEntryView struct {
	Time   string // UTC "2006-01-02 15:04:05", no nanoseconds
	Op     string // "write", "read", etc.
	Target string // file path or resource name
	DryRun bool   // true when the operation was a dry-run
}

// projectAuditEntries maps the last min(limit, len(entries)) audit entries to
// the metadata-only AuditEntryView. A limit <= 0 projects every entry. The
// returned slice never carries Hash/PrevHash/Sig (they are not fields of
// AuditEntryView), so the audit view cannot leak the tamper-evident chain
// (WEB-07 HARD FLOOR).
func projectAuditEntries(entries []audit.Entry, limit int) []AuditEntryView {
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:] // keep the last N
	}
	views := make([]AuditEntryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, AuditEntryView{
			Time:   e.Time.UTC().Format(auditTimeLayout),
			Op:     e.Op,
			Target: e.Target,
			DryRun: e.DryRun,
		})
	}
	return views
}
