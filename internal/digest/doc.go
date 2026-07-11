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

// Package digest computes a read-only, secret-free daily digest of the
// internal/audit hash-chain — the data model behind `abysslink diary`.
//
// The whole computation is a PURE function of ([]audit.Entry, DayWindow):
// no time.Now, no map-iteration order in the output, no file I/O. The command
// layer performs the I/O (resolve the log path, ReadLog) and passes the entries
// and the requested day window down; Compute filters, classifies, and summarizes
// them into a deterministic Digest. Running Compute (and marshalling the result)
// twice over the same input yields byte-identical output — there is no
// wall-clock field, categories are emitted in a fixed slug-sorted order, and
// notable events / cast paths are stably ordered.
//
// Each audit op maps to EXACTLY ONE category (see categorize) so per-category
// counts never double-count and always reconcile: Applied+DryRun == TotalEntries
// and sum(category.count) == TotalEntries. Unrecognized/future ops fall into the
// "other" catch-all so totals still reconcile and unknown activity is surfaced,
// never silently dropped.
//
// Secret-safety is structural: the Notable projection carries only
// {Time, Op, Target, Category, DryRun} — it cannot emit the chain digests
// (Hash/Sig/PrevHash/KeyEpoch). The single free-text field, Target, is treated
// as an opaque path/id (never opened or expanded) and passed through safeTarget,
// which bounds its length and redacts any secret-shaped value as defense in
// depth. The digest reflects ONLY what the audit chain recorded; it is not a
// complete activity log of the host.
package digest
