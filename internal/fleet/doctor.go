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

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/tailscale/hujson"
)

// v1LegacyAccounts is the known set of account names stored under
// service="abysslink" in the v1 keychain namespace (mirrors cmd_enroll.go).
// Used by mr-key-uniqueness to detect D-KN-02 coexistence.
var v1LegacyAccounts = []string{
	"ntfy-password",
	"anthropic-api-key",
	"code-server-password",
}

// DoctorChecks returns []backend.DoctorFinding for the three mr-* fleet
// isolation invariant checks. It mirrors the signature and append-each-check
// shape of backend.NetBirdDoctorChecks (PATTERNS §internal/fleet/doctor.go).
//
// Parameters:
//   - ctx: caller context (propagated to all blocking operations)
//   - cfg: current loaded config (cfg.Rigs is the source of truth)
//   - kc:  keychain store for legacy v1 coexistence probe (may be nil)
//   - acl: ACLManager for the active backend (may be nil — yields WARN)
//
// Backend-neutral: imports only stdlib + internal/config + internal/secrets +
// internal/backend interfaces — no concrete adapter (BKND-04 constraint).
func DoctorChecks(
	ctx context.Context,
	cfg *config.Config,
	kc secrets.KeychainStore,
	acl backend.ACLManager,
) []backend.DoctorFinding {
	var findings []backend.DoctorFinding
	findings = append(findings, checkMrRigIsolation(ctx, cfg, acl))
	findings = append(findings, checkMrTopicIsolation(cfg))
	findings = append(findings, checkMrKeyUniqueness(ctx, cfg, kc))
	return findings
}

// ── mr-rig-isolation ──────────────────────────────────────────────────────────

// checkMrRigIsolation calls acl.GetACL and asserts the read-back of the
// rig-to-rig deny EFFECT (Decision A1: absence-of-grant, not a rule name match).
// The Tailscale/Headscale HuJSON schema is allow-only / default-deny; isolation
// is expressed as the ABSENCE of any tag:laptop→tag:laptop grant.
//
// Severity mapping:
//   - DoctorFatal  — a tag:laptop→tag:laptop grant is present (isolation is broken)
//   - DoctorOK     — no rig-to-rig grant found (isolation is in effect)
//   - DoctorWarning — acl is nil or GetACL failed (cannot verify)
func checkMrRigIsolation(ctx context.Context, cfg *config.Config, acl backend.ACLManager) backend.DoctorFinding {
	const check = "mr-rig-isolation"
	const mod = "fleet"

	_ = cfg // cfg reserved for future per-rig backend-type dispatch

	if acl == nil {
		return backend.DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: backend.DoctorWarning,
			Message:  "ACL backend unavailable — cannot verify rig isolation (mr-rig-isolation)",
		}
	}

	raw, _, err := acl.GetACL(ctx)
	if err != nil {
		return backend.DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: backend.DoctorWarning,
			Message:  fmt.Sprintf("mr-rig-isolation: GetACL failed: %v", err),
		}
	}

	// Read-back-of-effect: parse grants and assert no tag:laptop→tag:laptop path.
	// This is the absence-of-grant assertion (Decision A1 from Plan 03 checkpoint).
	if grantErr := assertNoRigRigGrantFleet(raw); grantErr != nil {
		slog.DebugContext(ctx, "mr-rig-isolation: rig-to-rig grant found", "err", grantErr)
		return backend.DoctorFinding{
			Module:   mod,
			Check:    check,
			Severity: backend.DoctorFatal,
			Message: "mr-rig-isolation: tag:laptop→tag:laptop grant found in ACL — " +
				"rig-to-rig lateral movement is possible (T-14-13); " +
				"run abysslink enroll rig <name> --apply to re-push the absence-of-grant",
		}
	}

	slog.DebugContext(ctx, "mr-rig-isolation: no rig-to-rig grant found (isolation in effect)")
	return backend.DoctorFinding{
		Module:   mod,
		Check:    check,
		Severity: backend.DoctorOK,
		Message:  "mr-rig-isolation: no tag:laptop↔tag:laptop grant found — rig-to-rig isolation in effect (D-AI-01)",
	}
}

// fleetACLDoc is the minimal subset of an ACL document needed for the
// absence-of-grant assertion. Defined locally to avoid importing the
// tailscale sub-package (backend-neutral constraint BKND-04).
type fleetACLDoc struct {
	Grants []fleetACLGrant `json:"grants"`
}

type fleetACLGrant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
}

// assertNoRigRigGrantFleet parses the ACL HuJSON (or plain JSON) and returns an
// error if any grant has tag:laptop in both Src and Dst (bidirectional). Mirrors
// assertNoRigRigGrant in cmd_enroll.go (Decision A1).
//
// CR-03: Uses hujson.Standardize before json.Unmarshal so that Tailscale ACL
// documents containing C-style comments or trailing commas are handled correctly.
// A parse failure is FATAL — the caller must not downgrade to WARN on parse error;
// returning an error ensures checkMrRigIsolation surfaces DoctorFatal (fail closed).
func assertNoRigRigGrantFleet(raw []byte) error {
	// Standardize HuJSON → plain JSON (strips comments and trailing commas).
	std, err := hujson.Standardize(append([]byte(nil), raw...))
	if err != nil {
		return fmt.Errorf("cannot standardize HuJSON ACL (CR-03): %w", err)
	}

	var doc fleetACLDoc
	if err := json.Unmarshal(std, &doc); err != nil {
		// Parse failure is fatal — we cannot assert the absence-of-grant without
		// a successfully parsed document (fail closed, never downgrade to WARN).
		return fmt.Errorf("cannot parse ACL document: %w", err)
	}
	const laptopTag = "tag:laptop"
	for _, g := range doc.Grants {
		if containsStringFleet(g.Src, laptopTag) && containsStringFleet(g.Dst, laptopTag) {
			return fmt.Errorf("tag:laptop→tag:laptop grant present (rig-to-rig lateral movement)")
		}
	}
	return nil
}

// containsStringFleet reports whether haystack contains needle.
func containsStringFleet(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ── mr-topic-isolation ────────────────────────────────────────────────────────

// checkMrTopicIsolation performs a pairwise comparison of NtfyTopic across
// all enrolled rigs. A duplicate topic means two rigs share an ntfy channel —
// notifications (including HMAC-signed ones) would be readable by both rigs,
// violating information isolation (T-14-14, D-NI-01).
//
// Severity mapping:
//   - DoctorFatal — any two rigs share the same NtfyTopic
//   - DoctorOK    — all topics are distinct (or fewer than 2 rigs enrolled)
func checkMrTopicIsolation(cfg *config.Config) backend.DoctorFinding {
	const check = "mr-topic-isolation"
	const mod = "fleet"

	seen := make(map[string]string) // topic → rig name
	for _, rig := range cfg.Rigs {
		// CR-04: rigs with an empty NtfyTopic cannot be proven isolated — they
		// fall back to the shared "rig" topic in sendRigNotify, causing cross-tenant
		// notification leakage (T-14-14, D-NI-01). Fail FATAL, never skip silently.
		if rig.NtfyTopic == "" {
			return backend.DoctorFinding{
				Module:   mod,
				Check:    check,
				Severity: backend.DoctorFatal,
				Message: fmt.Sprintf(
					"mr-topic-isolation: rig %q has no ntfy_topic configured — "+
						"isolation cannot be verified; re-enroll with --apply to assign a unique topic (D-NI-01, T-14-14)",
					rig.Name,
				),
			}
		}
		if prev, ok := seen[rig.NtfyTopic]; ok {
			return backend.DoctorFinding{
				Module:   mod,
				Check:    check,
				Severity: backend.DoctorFatal,
				Message: fmt.Sprintf(
					"mr-topic-isolation: rigs %q and %q share ntfy topic %q — "+
						"each rig must have a unique topic (D-NI-01, T-14-14)",
					prev, rig.Name, rig.NtfyTopic,
				),
			}
		}
		seen[rig.NtfyTopic] = rig.Name
	}

	return backend.DoctorFinding{
		Module:   mod,
		Check:    check,
		Severity: backend.DoctorOK,
		Message:  "mr-topic-isolation: all enrolled rigs have distinct ntfy topics",
	}
}

// ── mr-key-uniqueness ─────────────────────────────────────────────────────────

// checkMrKeyUniqueness verifies that:
//  1. No two rigs derive the same RigService (keychain service name).
//     Because RigService(name) = "abysslink-rig-" + name, this is equivalent to
//     checking for duplicate rig names in cfg.Rigs.
//  2. No legacy v1 keychain entries (service="abysslink") coexist with named
//     rigs — coexistence means v1 migration is incomplete (D-KN-02).
//
// Severity mapping:
//   - DoctorFatal   — two rigs derive the same keychain service (duplicate rig names)
//   - DoctorWarning — named rigs coexist with surviving v1 service="abysslink" entries
//   - DoctorOK      — all services are unique and no v1 entries found
func checkMrKeyUniqueness(ctx context.Context, cfg *config.Config, kc secrets.KeychainStore) backend.DoctorFinding {
	const check = "mr-key-uniqueness"
	const mod = "fleet"

	// Step 1: pairwise-compare RigService(name) across enrolled rigs.
	seen := make(map[string]string) // service → rig name
	for _, rig := range cfg.Rigs {
		svc := RigService(rig.Name)
		if prev, ok := seen[svc]; ok {
			return backend.DoctorFinding{
				Module:   mod,
				Check:    check,
				Severity: backend.DoctorFatal,
				Message: fmt.Sprintf(
					"mr-key-uniqueness: rigs %q and %q derive the same keychain service %q — "+
						"rig names must be unique (T-14-15); rename the conflicting rig",
					prev, rig.Name, svc,
				),
			}
		}
		seen[svc] = rig.Name
	}

	// Step 2: detect legacy v1 coexistence (D-KN-02).
	// Only run if named rigs exist AND we have a keychain store.
	if len(cfg.Rigs) > 0 && kc != nil {
		for _, acct := range v1LegacyAccounts {
			if _, err := kc.Get(ctx, "abysslink", acct); err == nil {
				// A v1 entry still resolves while named rigs exist.
				return backend.DoctorFinding{
					Module:   mod,
					Check:    check,
					Severity: backend.DoctorWarning,
					Message: fmt.Sprintf(
						"mr-key-uniqueness: legacy v1 keychain entry abysslink/%s still present "+
							"alongside %d named rig(s) — migration may be incomplete (D-KN-02); "+
							"re-run abysslink enroll rig <name> --apply to complete migration",
						acct, len(cfg.Rigs),
					),
				}
			}
		}
	}

	return backend.DoctorFinding{
		Module:   mod,
		Check:    check,
		Severity: backend.DoctorOK,
		Message:  "mr-key-uniqueness: all rig keychain services are unique; no legacy v1 coexistence detected",
	}
}
