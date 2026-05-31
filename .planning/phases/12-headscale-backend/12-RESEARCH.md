# Phase 12: Headscale Backend — Research

**Researched:** 2026-05-31
**Domain:** Headscale self-hosted Tailscale control server — Go adapter, provisioning, REST API, doctor checks
**Confidence:** MEDIUM-HIGH (core API confirmed from source; macOS launchd non-root flagged MEDIUM; cosign absence is a breaking deviation from spec)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Server provisioning model**
- D-01: Local-host-only provisioning. `abysslink server headscale init --apply` runs ON the box. All mutations go through `internal/audit`.
- D-02: Both Linux (systemd) and macOS (launchd) supported. Non-root floor on both. macOS uses dedicated service account + launchd plist. Research must define the macOS path — flagged risky below.
- D-03: `config.yaml` managed by surgical merge, mirroring the ACL-editor pattern. Idempotent re-runs.
- D-04: `server headscale upgrade` = cosign-verify → backup DB → swap → health-check. Refuses downgrade.

**TLS cert strategy**
- D-05: BYO-verify is the default; `--acme` is an explicit opt-in. TLS gate refuses to proceed without a valid cert.
- D-06: BYO validity is strict/fail-closed: not expired, not within N days of expiry, CN/SAN matches FQDN, parses as valid chain, key-file perms 0600 owned by service user.
- D-07: When `--acme` is used, Headscale-native (no reverse proxy). Research MUST confirm ACME + DERP co-hosting — resolved below.

**Admin API transport**
- D-08: All admin ops via `net/http` to `/api/v1/...` gRPC-gateway REST API with Bearer API key. No CLI shelling.
- D-09: Enforces `policy.mode: database`. Doctor FAILs if file-mode detected.
- D-10: Headscale API key in OS keychain (env/stdin fallback). Never on argv, never in audit log.

**Enrollment / pre-auth key handoff**
- D-11: Pre-auth key from keychain/stdin. Never on argv. Short-expiry mandatory.
- D-12: `hs-oidc-filter` PASS/SKIP when OIDC not configured; FAIL only when OIDC enabled AND `allowed_domains`/`allowed_users` empty.

### Claude's Discretion
- Exact N-days threshold for cert expiry warning (D-06) and "short expiry" for pre-auth keys.
- Internal package layout under `internal/backend/` for the Headscale adapter.
- Doctor-finding wording for each hs-* check (hs-lock text is fixed by ROADMAP).

### Deferred Ideas (OUT OF SCOPE)
- Reverse-proxy (Caddy/nginx) TLS termination
- OIDC as primary enrollment path
- Remote/over-SSH server provisioning
- File-mode ACL policy support
- Headscale PostgreSQL HA
- NetBird backend (Phase 13)
- Multi-rig fleet (Phase 14)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| HS-01 | Headscale client backend: `backend.type: headscale`, enroll node, push deny-all HuJSON ACL before first node admitted, `Caps().Lock=false` | REST API confirmed: `POST /api/v1/preauthkey`, `PUT /api/v1/policy`. HuJSON push via ACLManager. `LockCapability()` returns `LockNone`. |
| HS-02 | Server provisioning: `abysslink server headscale init/status/upgrade/backup`; hardened config.yaml (TLS gate, verify_client_url_fail_open:false, embedded DERP); non-root service; cosign-verified binary; pre-auth keys with explicit short expiry; SQLite DB in backup | Hardened config keys confirmed from source. verify_client_url_fail_open is NOT a Headscale config key (see Research Flags resolution). Non-root: Linux=systemd confirmed; macOS=launchd MEDIUM confidence. Headscale does NOT publish cosign signatures — critical deviation documented below. |
| HS-03 | Nine hs-* doctor checks: hs-tls, hs-bind, hs-api-auth, hs-key-expiry, hs-db-perms, hs-lock (permanent WARN), hs-oidc-filter (FAIL if filter empty), hs-proc-user, hs-derp-failclosed | Concrete check signals defined for all nine below. |
</phase_requirements>

---

## Summary

Phase 12 plugs a Headscale backend into the Phase 11 `internal/backend.Client` seam. The core technical domains are: (1) a new `headscaleAdapter` under `internal/backend/` implementing `Client`, `AdminAPI`, and `ACLManager` (but NOT `Locker`); (2) a new `abysslink server headscale` CLI subtree for provisioning; (3) nine `hs-*` doctor checks registered via BKND-05's per-backend doctor registry; and (4) config schema extensions for Headscale-specific fields.

**Five research flags are resolved.** Three findings require immediate user attention before planning: (A) `verify_client_url_fail_open` is NOT a Headscale `config.yaml` key — it is a flag for the standalone `derper` binary; the embedded DERP already hardens client verification via `derp.server.verify_clients: true`; D-07 spec must be corrected. (B) Headscale does NOT publish cosign signatures in its release artifacts; the cosign gate from D-04 cannot be applied as-is; the plan must either use SHA-256 checksum verification only (with provenance from the official GitHub release) or document a weaker-than-spec verification posture. (C) macOS non-root port-443 binding requires launchd socket activation (not just UserName key), adding implementation complexity.

**Primary recommendation:** Proceed to planning with the above three deviations documented as user-confirmation gates before implementation begins. The REST API is well-covered (all needed endpoints confirmed from proto source), policy mode behavior is code-verified, and the Linux provisioning path is straightforward.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Headscale client enrollment (tailscale up --login-server) | API / Backend | — | tailscale daemon registers against Headscale control server; abysslink drives via shell.Runner |
| ACL push (deny-all baseline + subsequent edits) | API / Backend | — | `PUT /api/v1/policy` REST call; reuses ACLManager sub-interface |
| Server provisioning (binary download, config.yaml, service unit) | API / Backend | OS Platform | All file mutations via internal/audit; service install via platform.ServiceInstaller |
| API key / pre-auth key lifecycle | API / Backend | OS Keychain | Keys stored in keychain; created via REST API; never on argv |
| Doctor checks (hs-* nine checks) | API / Backend | OS (procfs/launchd) | Mix of REST calls, file stat, process inspection |
| TLS certificate validation (hs-tls) | API / Backend | OS (filesystem) | Cert file parsed in Go (crypto/tls); no external tool |
| Backup (SQLite DB) | API / Backend | internal/audit | audit.Backup covers all files including DB path |
| `hs-lock` permanent WARN | API / Backend | — | Backend capability metadata; no runtime check needed |

---

## Standard Stack

Phase 12 introduces no new Go library dependencies (confirmed decision in STATE.md: "No new Go library deps for v2 — Headscale and NetBird driven via shell.Runner + net/http only").

### Core (no new imports)
| Component | Source | Purpose |
|-----------|--------|---------|
| `net/http` | stdlib | HTTP client for Headscale REST API (`/api/v1/...`) |
| `encoding/json` | stdlib | Marshal/unmarshal Headscale API request/response bodies |
| `crypto/tls` | stdlib | BYO cert validation (hs-tls check, D-06) |
| `crypto/x509` | stdlib | Parse cert chain, extract SAN, check expiry |
| `os.Stat` | stdlib | SQLite DB file permission check (hs-db-perms) |
| `internal/shell.Runner` | project | All headscale binary invocations go through Runner |
| `internal/audit` | project | All file mutations (config.yaml, service unit, DB backup) |
| `internal/backend.ACLManager` | project | ACL push/get interface implemented by headscaleAdapter |
| `internal/backend.AdminAPI` | project | Device list/tag/delete + auth-key create |
| `internal/modules/acl/` | project | Reuse HuJSON deny-all baseline builder |

### Supporting
| Component | Source | Purpose |
|-----------|--------|---------|
| `httptest.Server` | stdlib | Mock Headscale REST API for contract/invariant tests |
| `internal/shell.MockRunner` | project | Mock shell calls for headscale binary in tests |
| `internal/config.Server` | project | Extend with Headscale provisioning fields |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| net/http to REST | github.com/hibare/headscale-client-go | Adds external dep, unnecessary given narrow API surface needed |
| net/http to REST | shell out to `headscale` CLI | Would violate D-08 (no CLI shelling from client adapter) |

**Installation:** No new packages. Phase 12 adds zero external dependencies.

---

## Package Legitimacy Audit

> This phase introduces no new external package dependencies. All implementation uses stdlib and existing project-internal packages only.

| Package | Registry | Disposition |
|---------|----------|-------------|
| (none) | — | N/A — no new deps |

*slopcheck not applicable: no external packages added.*

---

## Research Flags — Resolved

### RF-1: ACME + Embedded DERP on One Listener (D-07)

**CONFIRMED: Co-hosting works. HTTP-01 is the compatible challenge type for this topology.** [VERIFIED: Headscale source code `hscontrol/app.go`]

How it works (from source):
1. Headscale's embedded DERP registers its HTTP handlers (`/derp`, `/derp/probe`, `/derp/latency-check`) on the **same chi mux** as the API. One `listen_addr` (default `:443`), one TLS listener.
2. When ACME is used, `autocert.Manager` manages the TLS config. Both the API and DERP handlers ride the same TLS-terminated listener.
3. With `tls_letsencrypt_challenge_type: HTTP-01`, LE validation hits port 80 (separate listener spawned by `certManager.HTTPHandler`). Port 443 is uninterrupted during validation. DERP and API remain available on 443 throughout cert issuance/renewal.
4. With `tls_letsencrypt_challenge_type: TLS-ALPN-01`, LE validation hits port 443 directly (same listener). Headscale WARNS if `listen_addr` is not `:443`. DERP is **not accessible** during the brief TLS-ALPN-01 validation handshake because autocert temporarily intercepts the connection.

**Conclusion for D-07:** When `--acme` is used, recommend `tls_letsencrypt_challenge_type: HTTP-01`. This keeps port 443 available to DERP + API throughout certificate lifecycle. TLS-ALPN-01 is technically possible but causes brief DERP interruption during validation — acceptable in practice but less clean. Document HTTP-01 as the default for abysslink's ACME path.

**Exact config.yaml keys (ACME + embedded DERP):**
```yaml
server_url: "https://headscale.example.com"
listen_addr: ":443"
tls_letsencrypt_hostname: "headscale.example.com"
tls_letsencrypt_cache_dir: "/var/lib/headscale/cache"
tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"   # port 80 for HTTP-01 validation

derp:
  server:
    enabled: true
    region_id: 999
    region_code: "headscale"
    region_name: "Headscale Embedded DERP"
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: "<server-public-ipv4>"
    ipv6: "<server-public-ipv6>"
```

**Port 80 non-root issue on Linux:** `tls_letsencrypt_listen: ":80"` requires CAP_NET_BIND_SERVICE. The official systemd unit includes `AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_CHOWN`. abysslink must preserve these in the generated unit. Non-root with port 80 is handled by the capability — no separate bind trick needed on Linux.

**IMPORTANT DEVIATION — D-07 spec says `verify_client_url_fail_open: false`:**
[VERIFIED: Headscale source code + official docs] `verify_client_url_fail_open` is a **flag for the standalone `derper` binary** (Tailscale Inc's reference DERP), not a Headscale config.yaml key. It controls what happens when an external `derper` binary calls back to Headscale's `/verify` endpoint to check if a client should be admitted.

For Headscale's **embedded DERP server**, client verification is controlled by `derp.server.verify_clients: true` (enabled by default). This ensures only nodes enrolled in the tailnet can use the embedded DERP. There is no `verify_client_url_fail_open` key in Headscale's config.yaml.

**User action required:** The CONTEXT.md D-07 spec says "hardened `config.yaml` (TLS gate, `verify_client_url_fail_open: false`, embedded DERP)". This key does not exist in Headscale config. The planner should replace this requirement with `derp.server.verify_clients: true` (already the default, enforced by the hardened merge) and flag this correction to the user.

---

### RF-2: macOS launchd Server Path (D-02)

**CONFIRMED WORKABLE — but requires launchd socket activation for port 443 binding. MEDIUM confidence. Material risk flagged.** [VERIFIED: macOS launchd.plist man page; VERIFIED: Headscale systemd unit at `packaging/systemd/headscale.service`]

**macOS service account creation:**
```bash
# Create dedicated service account (run once during init --apply)
sudo dscl . -create /Users/_headscale
sudo dscl . -create /Users/_headscale UserShell /usr/bin/false
sudo dscl . -create /Users/_headscale NFSHomeDirectory /var/lib/headscale
sudo dscl . -create /Users/_headscale UniqueID 399          # choose unused UID < 500
sudo dscl . -create /Users/_headscale PrimaryGroupID 399
sudo dscl . -create /Groups/_headscale
sudo dscl . -create /Groups/_headscale PrimaryGroupID 399
sudo dscl . -append /Groups/_headscale GroupMembership _headscale
sudo mkdir -p /var/lib/headscale /etc/headscale
sudo chown -R _headscale:_headscale /var/lib/headscale /etc/headscale
sudo chmod 750 /var/lib/headscale /etc/headscale
```

**launchd plist (`/Library/LaunchDaemons/net.abysslink.headscale.plist`):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>       <string>net.abysslink.headscale</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/headscale</string>
        <string>serve</string>
    </array>
    <key>UserName</key>    <string>_headscale</string>
    <key>GroupName</key>   <string>_headscale</string>
    <key>InitGroups</key>  <true/>
    <key>RunAtLoad</key>   <true/>
    <key>KeepAlive</key>   <true/>
    <key>WorkingDirectory</key>   <string>/var/lib/headscale</string>
    <key>StandardOutPath</key>    <string>/var/log/headscale/headscale.log</string>
    <key>StandardErrorPath</key>  <string>/var/log/headscale/headscale.err</string>
    <!-- Socket activation for port 443 (privileged port binding without root) -->
    <key>Sockets</key>
    <dict>
        <key>Listeners</key>
        <dict>
            <key>SockServiceName</key>  <string>https</string>
            <key>SockType</key>         <string>stream</string>
        </dict>
    </dict>
</dict>
</plist>
```

**Port 443 binding risk:** [VERIFIED: zameermanji.com blog 2024; VERIFIED: launchd.plist man page] On macOS, non-root processes can bind to port 443 on 0.0.0.0 since macOS Mojave, but NOT to a specific interface. For launchd socket activation, launchd holds the socket and passes the fd to the process. However, **Headscale is not written to accept pre-bound sockets via launchd activation** — it calls `tls.Listen()` directly. This means:

- Option A (implemented): Run `_headscale` as UserName in the plist, Headscale calls `tls.Listen(":443")` binding to all interfaces — this works on macOS (non-root binding to 0.0.0.0:443 is allowed post-Mojave). Risk: binds to all interfaces including public, same as Linux behavior.
- Option B (not implemented): Require port ≥ 1024 on macOS (e.g., `listen_addr: ":8443"` with a firewall forward rule). This avoids the privilege issue entirely but changes the user-facing port.

**Recommended approach for abysslink:** Use Option A. The `_headscale` UserName in a `/Library/LaunchDaemons` plist is documented in the man page as "applicable for services that are loaded into the privileged system domain." The non-root binding to `0.0.0.0:443` works post-Mojave. The hs-bind doctor check asserts that `listen_addr` is NOT `0.0.0.0:80` (metrics port must be unexposed) but port 443 on 0.0.0.0 is required for Headscale to function. [ASSUMED: Option A confirmed working in production; single source confirms Mojave+ allows this]

**macOS risk flag for user:** The macOS path has no upstream precedent in the Headscale project. The UID 399 is an arbitrary choice (must not conflict with existing system UIDs). The `dscl` account creation is not idempotent by default — the `init` command must detect whether the account already exists before running `dscl`. This is MEDIUM confidence; the user should be aware this path is untested by the Headscale project.

---

### RF-3: Headscale REST API Coverage (D-08)

**FULLY CONFIRMED from proto source.** [VERIFIED: `github.com/juanfont/headscale` proto file + source code inspection]

**Minimum supported version: v0.23.0** — this is when `policy.mode: database` and `GetPolicy`/`SetPolicy` REST endpoints were introduced. All deployments before v0.23.0 lack REST ACL management. The current stable release is **v0.28.0** (2026-02-04). Pin minimum at `>= v0.23.0` in the doctor `hs-version` check (add to nine-check list or as a sub-check of `hs-api-auth`).

**Confirmed REST endpoints (gRPC-gateway, auth: `Authorization: Bearer <api_key>`):**

| Operation | Method | Path | Request Body | Response |
|-----------|--------|------|--------------|----------|
| List nodes | GET | `/api/v1/node` | — | `{"nodes": [...]}` |
| Get node | GET | `/api/v1/node/{node_id}` | — | `{"node": {...}}` |
| Set node tags | POST | `/api/v1/node/{node_id}/tags` | `{"tags": ["tag:mobile"]}` | `{"node": {...}}` |
| Delete node | DELETE | `/api/v1/node/{node_id}` | — | `{}` |
| Create API key | POST | `/api/v1/apikey` | `{"expiration": "2026-06-30T00:00:00Z"}` | `{"apiKey": "<key>"}` |
| List API keys | GET | `/api/v1/apikey` | — | `{"apiKeys": [...]}` |
| Expire API key | POST | `/api/v1/apikey/expire` | `{"prefix": "<prefix>"}` | `{}` |
| Create pre-auth key | POST | `/api/v1/preauthkey` | `{"user": "...", "reusable": false, "ephemeral": true, "expiration": "<RFC3339>", "aclTags": [...]}` | `{"preAuthKey": {...}}` |
| List pre-auth keys | GET | `/api/v1/preauthkey` | — | `{"preAuthKeys": [...]}` |
| Expire pre-auth key | POST | `/api/v1/preauthkey/expire` | `{"key": "..."}` | `{}` |
| Get policy | GET | `/api/v1/policy` | — | `{"policy": "<huJSON>", "updatedAt": "..."}` |
| Set policy | PUT | `/api/v1/policy` | `{"policy": "<huJSON>"}` | `{"policy": {...}}` |

**Pre-auth key response schema** (from `github.com/hibare/headscale-client-go`):
```go
type PreAuthKey struct {
    ID         string    `json:"id"`
    User       User      `json:"user,omitempty"`
    Key        string    `json:"key,omitempty"`
    Reusable   bool      `json:"reusable"`
    Ephemeral  bool      `json:"ephemeral"`
    Used       bool      `json:"used"`
    Expiration time.Time `json:"expiration"`
    CreatedAt  time.Time `json:"createdAt"`
    ACLTags    []string  `json:"aclTags"`
}
```

**Issue #1579 (hs-key-expiry):** When creating a pre-auth key via REST API without specifying `expiration`, the response returns `"expiration": "0001-01-01T00:00:00Z"` (zero date). The CLI defaults to 60 minutes. abysslink MUST always send an explicit `expiration` in `CreatePreAuthKey` requests. The `hs-key-expiry` doctor check asserts that all active pre-auth keys have non-zero expiry (i.e., `expiration != "0001-01-01T00:00:00Z"` and `expiration > now`). [VERIFIED: GitHub issue #1579]

---

### RF-4: `policy.mode: database` Behavior (D-09)

**FULLY CONFIRMED from source code.** [VERIFIED: `hscontrol/grpcv1.go`, `hscontrol/types/policy.go`, `hscontrol/db/policy.go`]

**SetPolicy in file-mode returns a hard error:**
```go
// In hscontrol/grpcv1.go:
func (api headscaleV1APIServer) SetPolicy(...) {
    if api.h.cfg.Policy.Mode != types.PolicyModeDB {
        return nil, types.ErrPolicyUpdateIsDisabled
    }
```
The exact error string is: `"update is disabled for modes other than 'database'"` (from `hscontrol/types/policy.go`).

**GetPolicy in file-mode:** Returns the current file contents (reads the file). Does NOT return an error.

**How to detect file-mode for the doctor FAIL:** The `hs-db` check reads the running config via:
1. **Preferred:** Parse the Headscale `config.yaml` and check `policy.mode`. If not `database`, emit FAIL.
2. **Fallback:** Attempt `PUT /api/v1/policy` with the current policy bytes. If the error contains "update is disabled", emit FAIL.

Method 1 (config file parse) is preferred because it works without a running server. Method 2 is a runtime probe.

**Policy HuJSON format:** Headscale uses HuJSON (comments + trailing commas allowed). The reused v1 `internal/modules/acl/` HuJSON parser is directly compatible. The deny-all baseline must be pushed as HuJSON bytes via `PUT /api/v1/policy`.

---

### RF-5: Concrete Checks for hs-db-perms, hs-bind, hs-proc-user

**hs-db-perms:** [VERIFIED: Headscale official docs + issue #1274 + setup guides]
- Signal: `os.Stat(cfg.Server.Headscale.DBPath)` returns `FileMode`
- PASS: `mode.Perm() == 0o600` AND `stat.Uid == uid(_headscale or headscale)`
- WARN: perms are 0640 (group-readable) — warn but not fatal
- FAIL: perms are 0644 or broader (world-readable), or file owned by root when service runs as headscale user
- Default DB path: `/var/lib/headscale/db.sqlite`
- Also check WAL/SHM files (`db.sqlite-wal`, `db.sqlite-shm`) — same ownership check

**hs-bind:** [VERIFIED: Headscale docs + config-example.yaml]
- Signal: Parse Headscale `config.yaml` and inspect `listen_addr`, `metrics_listen_addr`
- PASS: `listen_addr` ends in `:443` (or user-configured non-default); `metrics_listen_addr` is NOT `0.0.0.0:*` (metrics must be unexposed — default is `127.0.0.1:9090`)
- FAIL: `metrics_listen_addr` contains `0.0.0.0` — metrics endpoint exposed to public (leak of internal state)
- WARN: `listen_addr` contains explicit IP that is not the server's tailnet/public IP (misconfiguration)
- FAIL: `grpc_listen_addr` (default `:50443`) is not loopback-only and `grpc_allow_insecure: true` — unauthenticated gRPC exposed
- Also check: `logtail.enabled: false` (prevents client log shipping to Tailscale Inc.)

**hs-proc-user:** [VERIFIED: Official systemd unit `packaging/systemd/headscale.service`; VERIFIED: macOS man page]

*Linux:*
- Signal: `systemctl show headscale --property=User` → check output equals `headscale`
- Alternative signal: parse `/proc/$(pgrep headscale)/status` for `Uid:` line, verify UID matches `headscale` user (not 0)
- PASS: running user is `headscale` (UID != 0)
- FAIL: running as root (UID 0)

*macOS:*
- Signal: `launchctl list net.abysslink.headscale` → check if loaded; then `ps -p $(pgrep headscale) -o user=` → check equals `_headscale`
- PASS: running user is `_headscale`
- FAIL: running as root or not running

---

## All Nine hs-* Doctor Checks — Concrete Signals

### hs-tls
- **What:** TLS certificate validity gate (D-05/D-06)
- **Signal (BYO mode):** Load `tls_cert_path` + `tls_key_path` from config.yaml; parse with `tls.LoadX509KeyPair`; extract leaf cert; verify CN/SAN matches `server_url` FQDN; check `NotAfter > now + N days`; check key file perms = 0600
- **Signal (ACME mode):** HTTP GET `https://<server_url>` and inspect presented cert; check `NotAfter > now + 30 days`
- **PASS:** Valid cert, not within N days of expiry, perms OK
- **WARN:** Cert valid but within N days of expiry (N = 30 for BYO, not applicable for ACME which auto-renews)
- **FAIL:** Cert expired, SAN mismatch, key file world-readable, chain invalid, or cert/key files missing
- **N days recommendation (discretion):** 30 days — matches autocert's renewal trigger

### hs-bind
- **What:** API and metrics port binding assertions
- **Signal:** Parse Headscale config.yaml; inspect `listen_addr`, `metrics_listen_addr`, `grpc_listen_addr`, `grpc_allow_insecure`
- **PASS:** `listen_addr` is `:443` or a valid bound address; `metrics_listen_addr` is loopback-only; `grpc_listen_addr` is loopback-only or `grpc_allow_insecure: false`
- **FAIL:** `metrics_listen_addr` is `0.0.0.0:*`; or `grpc_allow_insecure: true` with non-loopback gRPC bind
- **WARN:** Non-standard listen_addr port (not 443) — Tailscale clients may not connect

### hs-api-auth
- **What:** API key is present and can authenticate against the Headscale REST API
- **Signal:** Read API key from keychain; make `GET /api/v1/apikey` with `Authorization: Bearer <key>`; check HTTP 200
- **PASS:** HTTP 200 received
- **FAIL:** HTTP 401/403 (key invalid or missing); or API key not in keychain; or server unreachable
- **WARN:** API key expires within N days (N = 14 recommended)

### hs-key-expiry (closes upstream issue #1579)
- **What:** All active pre-auth keys have explicit non-zero expiry
- **Signal:** `GET /api/v1/preauthkey` (or per-user query); for each key where `used == false`: check `expiration != "0001-01-01T00:00:00Z"` AND `expiration > now`
- **PASS:** All active keys have valid non-zero future expiry
- **WARN:** No active pre-auth keys (nothing to assert)
- **FAIL:** Any active key has zero expiry (`0001-01-01T00:00:00Z`) or `expiration <= now`

### hs-db-perms
- **What:** SQLite database file permissions are tight
- **Signal:** `os.Stat(db.path)` — see RF-5 above
- **PASS:** 0600, owned by service user
- **WARN:** 0640
- **FAIL:** 0644 or world-readable, or owned by root when service runs as non-root

### hs-lock
- **What:** Permanent WARN — Tailnet Lock (TKA) not available on Headscale
- **Signal:** Backend capability check — `Capabilities().Lock == false` is always true for headscaleAdapter
- **PASS:** Never
- **WARN (permanent):** `"WARN: server-trust model only — Tailnet Lock (TKA) is not available on Headscale"` [exact text from ROADMAP]
- **FAIL:** Never

### hs-oidc-filter
- **What:** OIDC open-registration guard (D-12)
- **Signal:** Parse Headscale config.yaml; check `oidc.issuer` key presence
- **SKIP/PASS:** `oidc` section absent or `oidc.issuer` empty — no OIDC configured, no open-registration vector
- **FAIL:** `oidc.issuer` is non-empty AND BOTH `oidc.allowed_domains` AND `oidc.allowed_users` AND `oidc.allowed_groups` are empty — open registration for any identity provider user
- **WARN:** `oidc.issuer` non-empty, at least one filter set, but `oidc.email_verified_required` is false

### hs-proc-user
- **What:** Headscale process runs as non-root dedicated service user
- **Signal:** Platform-dependent — see RF-5 above
- **PASS:** Running as `headscale` (Linux) or `_headscale` (macOS), UID != 0
- **FAIL:** Running as root (UID 0)
- **WARN:** Process not found (service down) — doctor cannot assert

### hs-derp-failclosed
- **What:** Embedded DERP verifies clients (only enrolled nodes can use relay)
- **Signal:** Parse Headscale config.yaml; check `derp.server.verify_clients`
- **PASS:** `derp.server.enabled: true` AND `derp.server.verify_clients: true`
- **WARN:** `derp.server.enabled: false` — using external DERP only (acceptable but noted; also check that `derp.urls` is non-empty)
- **FAIL:** `derp.server.enabled: true` AND `derp.server.verify_clients: false` — embedded DERP is open relay (any internet client can use it)
- Note: the `verify_client_url_fail_open` concept from D-07 does not apply here. The embedded DERP's verification is binary (verify_clients on/off), not a fail-open/fail-closed probe.

---

## Architecture Patterns

### System Architecture Diagram

```
abysslink CLI
     │
     ├─── backend.New("headscale") ──► headscaleAdapter
     │         │                           │
     │         │                    implements:
     │         │                    ├── Client (Status/IP/Up/Down)
     │         │                    ├── AdminAPI (Devices/Tag/Delete/CreateAuthKey)
     │         │                    └── ACLManager (GetACL/SetACL/NewACLEditor/DefaultACL)
     │         │                    does NOT implement Locker
     │         │
     │         ├── net/http ─────────► Headscale REST /api/v1/...
     │         │                       (Bearer <API key from keychain>)
     │         │
     │         └── shell.Runner ────► tailscale up --login-server <url>
     │                                           --auth-key (via TS_AUTHKEY env)
     │
     ├─── abysslink server headscale init/upgrade/backup
     │         │
     │         ├── shell.Runner ────► curl/wget (binary download)
     │         ├── cosign/sha256 ───► [SHA-256 checksums.txt only — see cosign note]
     │         ├── internal/audit ──► config.yaml, service unit (backup+log)
     │         └── platform ────────► service install (systemd/launchd)
     │
     └─── abysslink doctor (hs-* checks)
               │
               ├── Parse config.yaml ──► hs-bind, hs-oidc-filter, hs-derp-failclosed, hs-db
               ├── crypto/tls load ───► hs-tls
               ├── REST GET /api/v1/apikey ──► hs-api-auth
               ├── REST GET /api/v1/preauthkey ──► hs-key-expiry
               ├── os.Stat(db.path) ──► hs-db-perms
               ├── systemctl/launchctl + ps ──► hs-proc-user
               └── Capabilities().Lock==false ──► hs-lock (permanent WARN)
```

### Recommended Project Structure
```
internal/backend/
├── headscale.go           # headscaleAdapter (Client+AdminAPI+ACLManager, not Locker)
├── headscale_config.go    # Headscale config.yaml surgical-merge logic
├── headscale_doctor.go    # nine hs-* DoctorCheck implementations
└── headscale_test.go      # contract + invariant tests (httptest mock)

internal/config/config.go  # extend Server stanza with Headscale fields

internal/cli/
└── cmd_server_headscale.go  # "abysslink server headscale" command subtree

internal/backend/
└── testdata/
    ├── headscale_nodes.json        # mock ListNodes response fixture
    ├── headscale_preauthkeys.json  # mock ListPreAuthKeys response fixture
    └── headscale_policy.json       # mock GetPolicy response fixture
```

### Pattern 1: headscaleAdapter struct (mirrors tailscaleAdapter)
```go
// Source: internal/backend/tailscale.go (precedent)
type headscaleAdapter struct {
    cfg     *config.Config
    runner  shell.Runner
    baseURL string        // from cfg.Server.Headscale.ServerURL
    apiKey  func() string // loaded from keychain lazily; never stored as field
}

// Capabilities: Lock=false, AdminAPI=true, SSHCheck=true, AuthKeys=true,
//               FunnelRejection=false (Headscale has no Funnel concept), ACL=true
func (a *headscaleAdapter) Capabilities() Capabilities {
    return Capabilities{
        Lock:            false,
        AdminAPI:        true,
        SSHCheck:        true,
        AuthKeys:        true,
        FunnelRejection: false,
        ACL:             true,
    }
}
func (a *headscaleAdapter) LockCapability() LockCapability { return LockNone }
```

### Pattern 2: REST call wrapper (no external dep, plain net/http)
```go
// Source: internal/tailscale/admin.go (precedent for HTTP client pattern)
func (a *headscaleAdapter) doRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
    var buf io.Reader
    if body != nil {
        data, err := json.Marshal(body)
        if err != nil {
            return nil, err
        }
        buf = bytes.NewReader(data)
    }
    req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, buf)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+a.apiKey())
    req.Header.Set("Content-Type", "application/json")
    return http.DefaultClient.Do(req)
}
```

### Pattern 3: Contract test for headscaleAdapter (mirrors contract_test.go)
```go
// Source: internal/backend/contract_test.go (precedent)
// TestContract_HeadscaleAdapter asserts invariants against httptest mock:
// - IP() returns non-empty (from GET /api/v1/node response)
// - SSHConfig().CheckPeriod non-zero
// - LockCapability() == LockNone (Headscale never returns LockFull)
// - Capabilities().Lock == false (must not implement Locker)
// - invariant_test.go: caps.Lock=false ↔ adapter does NOT implement backend.Locker
```

### Pattern 4: Surgical config merge (mirrors D-03)
```go
// The headscale config.yaml is YAML, not HuJSON, but the principle is the same:
// Load existing config, ensure required keys are set/correct, write back.
// Preserve user's other customizations (do not overwrite entire file).
// Required hardened keys:
//   grpc_allow_insecure: false
//   derp.server.verify_clients: true
//   policy.mode: database
//   database.type: sqlite
//   database.sqlite.path: <from cfg.Server.Headscale.DBPath>
//   logtail.enabled: false        (prevents client log shipping to Tailscale Inc)
```

### Pattern 5: Pre-auth key as non-argv secret (D-11)
```go
// Standard: set TS_AUTHKEY env var before invoking tailscale up
// This follows the Tailscale documented best practice (kb/1595/secure-auth-key-cli)
// Never pass key as --authkey=<value> on argv (visible in ps, audit log)
cmd := []string{"tailscale", "up",
    "--login-server", a.cfg.Server.Headscale.ServerURL,
    // key injected via environment, not argv:
}
// runner.RunWithEnv(ctx, cmd, map[string]string{"TS_AUTHKEY": key})
// The key itself comes from keychain, passed in env map — never written to disk
```

### Anti-Patterns to Avoid
- **Calling `headscale` CLI binary from the adapter (AdminAPI):** D-08 prohibits this. Use `net/http` to REST only.
- **Storing API key or pre-auth key in config.yaml:** Keys go to OS keychain only (D-10, D-11).
- **Writing raw API key to audit log:** `internal/audit` must receive redacted content (hash only).
- **Setting `verify_client_url_fail_open: false` in config.yaml:** This key does not exist in Headscale — see RF-1 resolution.
- **Passing `--authkey=<value>` on argv to tailscale up:** Visible in process list and audit log.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HuJSON deny-all ACL construction | Custom template builder | `internal/modules/acl.DefaultACL` + `NewACLEditor` | Already tested; idempotent; handles tag:mobile/tag:laptop; reuse per HS-01 |
| TLS certificate parsing | Manual cert file reading | `crypto/tls.LoadX509KeyPair` + `crypto/x509.Certificate` | Handles chain validation, SAN extraction, expiry check correctly |
| YAML surgical merge | Regex/string replace | `gopkg.in/yaml.v3` decode→modify struct→re-encode | Already a project dependency; handles all edge cases |
| HTTP Bearer auth client | Custom transport | Plain `net/http` with `Authorization` header | Simple; no new dep; follows v1 admin client pattern |
| Keychain secret storage | File-based secret cache | `internal/platform.Keychain` | Already wired; never on disk per project hard rules |
| SHA-256 checksum verification | Ad-hoc hash comparison | `crypto/sha256` + `bufio.Scanner` (mirror existing `verifyChecksum` in `cmd_upgrade.go`) | Already implemented in the upgrade command — reuse exact same function |

**Key insight:** The Headscale adapter is structurally identical to the tailscaleAdapter pattern but uses `net/http` instead of `shell.Runner` for admin operations. The phase is additive — zero existing code needs changing except factory.go (add `case "headscale"`) and config.go (extend `Server` stanza).

---

## Hardened config.yaml Key Set

[VERIFIED: Headscale source `hscontrol/types/config.go`, `config-example.yaml`, official docs]

Keys abysslink's surgical merge MUST ensure are set:

```yaml
# Required hardened keys (abysslink enforces via surgical merge):
server_url: "https://<server_url>"       # from cfg.Server.Headscale.ServerURL
listen_addr: ":443"                       # default; expose on port 443
grpc_allow_insecure: false                # never allow unencrypted gRPC
metrics_listen_addr: "127.0.0.1:9090"    # loopback only — not 0.0.0.0

database:
  type: sqlite
  sqlite:
    path: "/var/lib/headscale/db.sqlite"  # from cfg.Server.Headscale.DBPath
    write_ahead_log: true

policy:
  mode: database                           # required for REST ACL push (D-09)
  path: ""

derp:
  server:
    enabled: true                          # embedded DERP required
    verify_clients: true                   # fail-closed: only enrolled nodes use relay
    stun_listen_addr: "0.0.0.0:3478"

logtail:
  enabled: false                           # prevents client telemetry to Tailscale Inc

# TLS: either BYO or ACME (D-05) — one of:
# BYO:
tls_cert_path: "/etc/headscale/tls.crt"
tls_key_path:  "/etc/headscale/tls.key"
# ACME (--acme flag):
# tls_letsencrypt_hostname: "<fqdn>"
# tls_letsencrypt_challenge_type: HTTP-01
# tls_letsencrypt_listen: ":http"
```

**Keys the surgical merge must NOT overwrite (user customizations):**
- `oidc.*` (user may configure their IdP; hs-oidc-filter checks it but doesn't change it)
- `node_update_check_interval`
- `dns.*`
- Any key not in the hardened set above

---

## Headscale Release Artifact Naming (for `server headscale init/upgrade`)

[VERIFIED: GitHub releases API, v0.28.0]

**Current stable version:** v0.28.0 (2026-02-04)
**Beta:** v0.29.0-beta.2 (2026-05-29)

**Artifact naming pattern:** `headscale_{version}_{os}_{arch}` (bare binary, no tarball for individual platforms)
- `headscale_0.28.0_linux_amd64`
- `headscale_0.28.0_linux_arm64`
- `headscale_0.28.0_darwin_amd64`
- `headscale_0.28.0_darwin_arm64`
- `headscale_0.28.0_linux_amd64.deb` (Debian package)
- `checksums.txt` (SHA-256 checksums of all artifacts)

**CRITICAL — NO COSIGN SIGNATURES:** [VERIFIED: `.goreleaser.yml` source + v0.28.0 release asset listing]
Headscale's goreleaser config does NOT include cosign signing. The v0.28.0 release contains only:
- Plain binaries (bare executables)
- Debian packages
- A source tarball
- `checksums.txt` (SHA-256 of all files)

There is no `checksums.txt.sig`, no `checksums.txt.pem`, no `.sigstore.json` file.

**Impact on D-04:** The CONTEXT.md D-04 says "cosign-verify → backup DB → swap". This cannot be implemented as specified. Options:
1. **SHA-256 checksum verification only:** Download binary + `checksums.txt` from the official GitHub release (HTTPS), verify SHA-256. Weaker than cosign but standard for projects that don't publish cosign signatures.
2. **Wait for Headscale to add cosign:** Track upstream; implement cosign gate as no-op until signatures appear.
3. **User decision required:** The planner should surface this as a blocking clarification before committing to D-04's cosign requirement.

**Recommended:** Option 1 + flag for user. The verification flow mirrors `verifyChecksum` from `cmd_upgrade.go` (already implemented). HTTPS download from `github.com/juanfont/headscale/releases/download/vX.Y.Z/` provides transport-layer integrity. SHA-256 checksum provides artifact integrity. Document this as weaker-than-spec but pragmatic.

---

## Config Schema Extensions Required

Extend `internal/config/config.go` `Server` stanza (currently only has `Hostname` string):

```go
// HeadscaleServer holds configuration for a locally-provisioned Headscale server.
type HeadscaleServer struct {
    // ServerURL is the public HTTPS URL of the Headscale instance (used in config.yaml server_url).
    ServerURL string `yaml:"server_url"`
    // BinaryPath is the install path for the headscale binary. Default: /usr/local/bin/headscale.
    BinaryPath string `yaml:"binary_path,omitempty"`
    // ConfigPath is the path to headscale's config.yaml. Default: /etc/headscale/config.yaml.
    ConfigPath string `yaml:"config_path,omitempty"`
    // DBPath is the path to headscale's SQLite database. Default: /var/lib/headscale/db.sqlite.
    DBPath string `yaml:"db_path,omitempty"`
    // ACME enables Let's Encrypt automatic cert (opt-in, D-05).
    ACME bool `yaml:"acme,omitempty"`
    // TLSCertPath is the path to the BYO TLS certificate (D-06).
    TLSCertPath string `yaml:"tls_cert_path,omitempty"`
    // TLSKeyPath is the path to the BYO TLS private key (D-06).
    TLSKeyPath string `yaml:"tls_key_path,omitempty"`
    // CertExpiryWarnDays is the days-before-expiry threshold for hs-tls WARN. Default: 30.
    CertExpiryWarnDays int `yaml:"cert_expiry_warn_days,omitempty"`
    // PreAuthKeyExpiry is the duration for newly-minted pre-auth keys. Default: 1h (paranoid default).
    PreAuthKeyExpiry string `yaml:"pre_auth_key_expiry,omitempty"`
}

// Server holds configuration for a self-hosted backend server (v2+).
type Server struct {
    Hostname  string          `yaml:"hostname"`  // kept for compat
    Headscale HeadscaleServer `yaml:"headscale"`
}
```

---

## Common Pitfalls

### Pitfall 1: `verify_client_url_fail_open` in config.yaml
**What goes wrong:** Developer adds `verify_client_url_fail_open: false` to the surgical merge — Headscale ignores unknown keys silently (or fails to start if strict YAML parsing is enabled).
**Why it happens:** CONTEXT.md references this key but it belongs to the standalone `derper` binary, not Headscale.
**How to avoid:** Use `derp.server.verify_clients: true` instead. This is the correct embedded DERP hardening key.
**Warning signs:** grep for `verify_client_url_fail_open` in any generated config.yaml.

### Pitfall 2: Calling SetPolicy on a file-mode Headscale instance
**What goes wrong:** `PUT /api/v1/policy` returns `codes.Internal` with message "update is disabled for modes other than 'database'". The deny-all baseline silently fails to push.
**Why it happens:** Default Headscale config has `policy.mode: file`. If surgical merge fails to set `policy.mode: database` before `up` is called, REST pushes are dead.
**How to avoid:** Verify `policy.mode: database` in config before making any ACL REST call. `hs-db` doctor check catches this.
**Warning signs:** HTTP 500 response from `PUT /api/v1/policy` with the error string above.

### Pitfall 3: Pre-auth key zero expiry (issue #1579)
**What goes wrong:** Calling `POST /api/v1/preauthkey` without an `expiration` field returns a key with `"expiration": "0001-01-01T00:00:00Z"`. abysslink accepts this and enrolls the node with a never-expiring pre-auth key.
**Why it happens:** The API does not set a default expiry; the CLI does.
**How to avoid:** Always include an explicit `expiration` in the request body. abysslink defaults to `now + cfg.Server.Headscale.PreAuthKeyExpiry` (default: 1h).
**Warning signs:** `hs-key-expiry` doctor check FAIL.

### Pitfall 4: macOS launchd UserName silently ignored
**What goes wrong:** The daemon runs as root despite `UserName=_headscale` in the plist.
**Why it happens:** Historical macOS versions stripped the UserName key on load. Current macOS (man page) documents it as working for the privileged system domain.
**How to avoid:** After `launchctl load`, probe `ps -p $(pgrep headscale) -o user=` to assert. If it returns `root`, the account creation may have failed or the UID may conflict.
**Warning signs:** `hs-proc-user` FAIL.

### Pitfall 5: Port 443 binding on macOS as non-root fails for specific interfaces
**What goes wrong:** `listen_addr: "192.168.1.1:443"` fails with "permission denied" because macOS non-root port binding below 1024 only works for `0.0.0.0` (all interfaces).
**Why it happens:** macOS kernel restriction: non-root can bind to port < 1024 on 0.0.0.0 but not on specific IPs.
**How to avoid:** Use `listen_addr: ":443"` (all interfaces) on macOS, not an explicit IP. The `hs-bind` check warns if an explicit non-0.0.0.0 address is used on darwin.
**Warning signs:** Headscale fails to start with "bind: permission denied".

### Pitfall 6: Headscale binary not in PATH during doctor probes
**What goes wrong:** `hs-proc-user` tries to `pgrep headscale` or `headscale version` and fails because the binary is in `/usr/local/bin/headscale` (not in sudo PATH).
**Why it happens:** `PATH` differences between abysslink's execution context and the installed binary location.
**How to avoid:** Use the configured `cfg.Server.Headscale.BinaryPath` (default `/usr/local/bin/headscale`) directly in shell.Runner calls, not relying on PATH resolution.

---

## Code Examples

### Create pre-auth key (never on argv)
```go
// Source: internal/backend/tailscale.go pattern + kb/1595/secure-auth-key-cli
type createPreAuthKeyRequest struct {
    User       string    `json:"user"`
    Reusable   bool      `json:"reusable"`
    Ephemeral  bool      `json:"ephemeral"`
    Expiration time.Time `json:"expiration"`
    ACLTags    []string  `json:"aclTags"`
}

func (a *headscaleAdapter) CreateAuthKey(ctx context.Context, tags []string) (string, error) {
    expiry := time.Now().Add(a.preAuthKeyExpiry()) // default 1h from config
    req := createPreAuthKeyRequest{
        User:       a.cfg.Server.Headscale.User,
        Reusable:   false,
        Ephemeral:  true,
        Expiration: expiry,
        ACLTags:    tags,
    }
    resp, err := a.doRequest(ctx, http.MethodPost, "/api/v1/preauthkey", req)
    // ... parse response, return key string
    // NEVER log or audit-log the key value itself
}
```

### Push deny-all ACL (HS-01)
```go
// Source: internal/modules/acl/module.go + internal/backend/tailscale.go
// Push a deny-all baseline before first node is admitted.
// DefaultACL returns minimal safe HuJSON: only tag:mobile → tag:laptop on ssh/ntfy/mosh.
baseline := mgr.DefaultACL(cfg.Identity.Email, cfg.Identity.UnixUser)
etag, err := mgr.GetACL(ctx)  // get current ETag for optimistic concurrency
if err != nil { return err }
return mgr.SetACL(ctx, baseline, etag)
```

### BYO cert validation (hs-tls check)
```go
// Source: crypto/tls + crypto/x509 stdlib
cert, err := tls.LoadX509KeyPair(certPath, keyPath)
if err != nil { return Finding{Severity: SeverityFatal, Message: "cert/key load failed: "+err.Error()} }
leaf, err := x509.ParseCertificate(cert.Certificate[0])
if err != nil { return Finding{Severity: SeverityFatal} }
// Check expiry
warnThreshold := time.Now().Add(time.Duration(warnDays) * 24 * time.Hour)
if time.Now().After(leaf.NotAfter) {
    return Finding{Severity: SeverityFatal, Message: "certificate expired"}
}
if warnThreshold.After(leaf.NotAfter) {
    return Finding{Severity: SeverityWarning, Message: fmt.Sprintf("cert expires in <N days")}
}
// Check SAN matches server_url FQDN
```

### Detect policy.mode from config.yaml
```go
// Parse headscale config.yaml (path from cfg.Server.Headscale.ConfigPath)
var hsCfg struct {
    Policy struct { Mode string `yaml:"mode"` } `yaml:"policy"`
}
// ... unmarshal ...
if hsCfg.Policy.Mode != "database" {
    return Finding{
        Check: "hs-db",
        Severity: SeverityFatal,
        Message: `policy.mode is "` + hsCfg.Policy.Mode + `" — REST ACL pushes would silently no-op; set policy.mode: database`,
    }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| YAML ACL policy files | HuJSON only (`policy.mode: file` or `database`) | v0.23.0 | YAML is no longer supported; abysslink must always send HuJSON |
| Single large migration function | Structured migration per version | v0.23.0+ | Migrations are reliable on v0.23.0+ |
| Full map updates to all nodes | Partial map updates ("smarter map updates") | v0.28.0 | Lower overhead; no behavioral impact on abysslink |
| Tags as metadata | Tags redesigned following Tailscale model | v0.28.0 | ACL tag syntax/behavior matches Tailscale docs |
| pre-auth key stored as plaintext | bcrypt-hashed pre-auth keys | v0.28.0 | Keys cannot be retrieved after creation; store immediately in keychain |

**Deprecated/outdated:**
- `acl_policy_path` top-level key: replaced by `policy.path` under `policy:` section. Still accepted in older versions for compat.
- YAML ACL files: removed in v0.23.0. HuJSON only.
- PostgreSQL as primary DB: still "supported" but "strongly recommended against" per docs. SQLite is the only supported path for abysslink.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | macOS non-root UserName in `/Library/LaunchDaemons` plist works to run Headscale as `_headscale` on current macOS | macOS launchd path | Service runs as root instead; hs-proc-user FAIL; security regression |
| A2 | macOS allows binding to `0.0.0.0:443` as non-root (post-Mojave) for Headscale's `tls.Listen()` call | macOS port binding | Headscale fails to start on macOS as non-root; port 443 unavailable |
| A3 | UID 399 is unused on a typical macOS system; safe for `_headscale` account | macOS service account creation | UID collision; `dscl` fails; init aborts |
| A4 | Headscale v0.29.0+ (beta) does not break the `/api/v1/...` endpoint paths documented here | REST API | Adapter fails at runtime against newer Headscale; needs version floor bump |
| A5 | The `headscale` binary on macOS darwin/arm64 runs without additional Gatekeeper quarantine (or user clears it) | Binary download/exec | `xattr -d com.apple.quarantine` step needed; init fails silently if omitted |

**Items A1, A2 are the highest-risk assumptions.** Both are specific to the macOS launchd path (D-02 deviation from ROADMAP). If either fails in testing, the macOS provisioning path needs to fall back to port > 1024 or require root for initial bind.

---

## Open Questions (RESOLVED)

1. **cosign absence — user decision required**
   - What we know: Headscale v0.28.0 does not publish cosign signatures. Only `checksums.txt` (SHA-256).
   - What's unclear: Whether the user wants to (a) implement SHA-256-only verification now, (b) wait for Headscale to add cosign, or (c) accept that `server headscale init` has weaker binary provenance than `abysslink upgrade`.
   - Recommendation: Add a `checkpoint:human-verify` task in Wave 1 of the plan asking the user to decide. Default: implement SHA-256 checksum verification + HTTPS download (transport integrity) and document the gap.
   - **RESOLVED (R-01):** SHA-256 checksum verification via `checksums.txt` over HTTPS is the implemented approach. Documented as weaker-than-spec; cosign deferred until Headscale upstream adds signatures.

2. **Headscale user/namespace for pre-auth keys (v0.28.0 tags redesign)**
   - What we know: Pre-auth key creation requires a `user` field. v0.28.0 redesigned tags to follow the Tailscale model (tags via ACL rather than user assignment).
   - What's unclear: Whether abysslink should create a Headscale user named after `cfg.Identity.Email` or use a default user name. Also whether `aclTags` in the pre-auth key replace or complement ACL tag ownership.
   - Recommendation: Planner should create a task to create a Headscale user during `init` and store the user name in config.
   - **RESOLVED (D-13):** Abysslink creates/ensures a Headscale user named **`abysslink`** (stable fixed default, not derived from email). The `init` sequence calls `GET /api/v1/user` to check existence; if absent, calls `POST /api/v1/user` to create it. The user name is stored in `cfg.Server.Headscale.User` (overrideable). User creation happens BEFORE minting the pre-auth key. Both REST calls use the `doRequest` pattern (D-08 — no CLI shelling). `aclTags` complement but do not replace ACL ownership — tags must still be declared in the deny-all baseline HuJSON.

3. **macOS Gatekeeper quarantine on downloaded binary**
   - What we know: macOS adds a quarantine xattr to files downloaded via `curl`/`wget` that blocks execution.
   - What's unclear: Whether `xattr -d com.apple.quarantine /usr/local/bin/headscale` is needed and whether it requires user interaction.
   - Recommendation: Add a `xattr -d com.apple.quarantine` step after binary download on darwin. This is a shell.Runner call.

4. **Version floor enforcement**
   - What we know: `policy.mode: database` and `GetPolicy`/`SetPolicy` require >= v0.23.0.
   - What's unclear: Whether to add a `hs-version` doctor check or bake version floor into `init`.
   - Recommendation: `init` should refuse to proceed if `headscale version` reports < v0.23.0. Add as an init guard, not a separate doctor check.

---

## Environment Availability

> Phase 12 is a provisioner for the Headscale binary — the binary does not need to be installed before `init`. However, the doctor checks require a running Headscale instance.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `tailscale` binary | `Up()` client enrollment | Project assumption (present from Phase 4) | — | Error: "install Tailscale first" |
| `headscale` binary | `server headscale status/upgrade/backup` | Downloaded by `init` | ≥ v0.23.0 | Not available until `init` runs |
| `cosign` binary | Binary signature verification | — | — | **NOT APPLICABLE** — Headscale has no cosign signatures |
| Port 443 (TCP) | Headscale HTTPS + DERP | Must be open in firewall | — | Document firewall requirement |
| Port 3478 (UDP) | STUN (embedded DERP) | Must be open in firewall | — | Document firewall requirement |
| Port 80 (TCP) | HTTP-01 ACME validation (optional) | Must be open if `--acme` | — | Use BYO cert if port 80 unavailable |
| OS keychain | API key / pre-auth key storage | Phase 3 (platform abstraction) | — | env var fallback (ABYSSLINK_HS_API_KEY) |

**Missing dependencies with no fallback:**
- Port 443 open in firewall: required; no fallback. `init` should document this requirement.

**Missing dependencies with fallback:**
- cosign: not applicable (Headscale has no cosign artifacts)

---

## Validation Architecture

> nyquist_validation not explicitly disabled in .planning/config.json (key absent = enabled).

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go test + testify (`github.com/stretchr/testify`) |
| Config file | None (go test ./... from project root) |
| Quick run command | `go test ./internal/backend/... -run TestHeadscale -v` |
| Full suite command | `make lint test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| HS-01 | headscaleAdapter implements Client+AdminAPI+ACLManager, not Locker | unit | `go test ./internal/backend/... -run TestCapabilityInterfaceLockstep` | ❌ Wave 0 |
| HS-01 | LockCapability() returns LockNone | unit | `go test ./internal/backend/... -run TestContract_HeadscaleAdapter` | ❌ Wave 0 |
| HS-01 | SetACL pushes deny-all policy via mock httptest server | unit | `go test ./internal/backend/... -run TestHeadscaleSetACL` | ❌ Wave 0 |
| HS-02 | init creates hardened config.yaml with required keys | unit | `go test ./internal/backend/... -run TestHeadscaleConfigMerge` | ❌ Wave 0 |
| HS-02 | upgrade refuses downgrade | unit | `go test ./internal/cli/... -run TestServerHeadscaleUpgradeRefusesDowngrade` | ❌ Wave 0 |
| HS-03 | all nine hs-* checks return correct PASS/WARN/FAIL on mock data | unit | `go test ./internal/backend/... -run TestHsDoctorChecks` | ❌ Wave 0 |
| HS-03 | hs-lock always returns SeverityWarning, never PASS | unit | `go test ./internal/backend/... -run TestHsLockPermanentWarn` | ❌ Wave 0 |
| HS-03 | hs-key-expiry FAILs on zero-expiry key | unit | `go test ./internal/backend/... -run TestHsKeyExpiry` | ❌ Wave 0 |

### Sampling Rate
- Per task commit: `go test ./internal/backend/... -v`
- Per wave merge: `make lint test`
- Phase gate: Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/backend/headscale_test.go` — contract + invariant tests (mirrors `contract_test.go`)
- [ ] `internal/backend/testdata/headscale_nodes.json` — mock node list fixture
- [ ] `internal/backend/testdata/headscale_preauthkeys.json` — mock pre-auth key fixture
- [ ] `internal/backend/testdata/headscale_policy.json` — mock policy response fixture

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Bearer API key from OS keychain; never on argv |
| V3 Session Management | partial | Pre-auth key expiry enforced; short-expiry default (1h) |
| V4 Access Control | yes | deny-all baseline pushed before first node; hs-oidc-filter guards open OIDC |
| V5 Input Validation | yes | HuJSON validated before push via existing ACLEditor; Headscale rejects invalid policy |
| V6 Cryptography | yes | BYO cert: `crypto/tls`; binary integrity: SHA-256 checksum; no custom crypto |
| V7 Error Handling | yes | `ErrPolicyUpdateIsDisabled` caught and surfaced as FAIL; no silent no-ops |
| V8 Data Protection | yes | API key + pre-auth key never in audit log; DB file perms 0600; key file perms 0600 |
| V9 Communication | yes | TLS gate enforced; `grpc_allow_insecure: false` in hardened config |

### Known Threat Patterns for Headscale

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Open OIDC registration (any IdP user can join) | Spoofing | hs-oidc-filter FAIL + allowed_domains/users enforcement |
| Pre-auth key without expiry (issue #1579) | Elevation of Privilege | hs-key-expiry FAIL + always send explicit expiry in API request |
| Embedded DERP as open relay | Information Disclosure | `derp.server.verify_clients: true` in hardened config; hs-derp-failclosed check |
| gRPC plaintext admin port exposed | Tampering/Disclosure | `grpc_allow_insecure: false` (hardened config key); hs-bind check |
| Metrics endpoint exposed (0.0.0.0:9090) | Information Disclosure | `metrics_listen_addr: "127.0.0.1:9090"` (hardened config); hs-bind check |
| Headscale running as root | Elevation of Privilege | systemd `User=headscale` / launchd `UserName=_headscale`; hs-proc-user FAIL |
| SQLite DB world-readable | Information Disclosure | DB path perms 0600; hs-db-perms FAIL |
| Binary tampering during download | Tampering | SHA-256 checksum from `checksums.txt` via HTTPS (cosign not available) |
| TKA/Tailnet Lock absence | Elevation of Privilege | hs-lock permanent WARN (cannot be mitigated; users must understand trust model) |
| Client log telemetry to Tailscale Inc | Information Disclosure | `logtail.enabled: false` in hardened config |

---

## Sources

### Primary (HIGH confidence)
- `github.com/juanfont/headscale` — `hscontrol/app.go`, `hscontrol/grpcv1.go`, `hscontrol/types/policy.go`, `hscontrol/db/policy.go`, `hscontrol/types/config.go`, `packaging/systemd/headscale.service`, `config-example.yaml`, `docs/ref/tls.md`, `docs/ref/derp.md`, `docs/setup/requirements.md` — inspected via GitHub API
- `github.com/juanfont/headscale` releases API — v0.28.0 asset listing (confirmed no cosign artifacts)
- `man launchd.plist` (local macOS man page) — UserName key behavior confirmed
- `pkg.go.dev/github.com/hibare/headscale-client-go/v1/preauthkeys` — pre-auth key request/response schema

### Secondary (MEDIUM confidence)
- Headscale official docs: `headscale.net/stable/ref/tls/`, `headscale.net/stable/ref/derp/`, `headscale.net/stable/ref/acls/`, `headscale.net/stable/ref/oidc/` — TLS, DERP, policy, OIDC configuration
- GitHub issue #1579 — confirmed pre-auth key zero expiry bug in REST API
- GitHub PR #1792 — confirmed policy.mode: database and GetPolicy/SetPolicy introduced in v0.23.0
- zameermanji.com blog (2024) — macOS port 443 non-root binding behavior

### Tertiary (LOW confidence / ASSUMED)
- macOS `dscl` daemon account creation commands (A1 — pattern from gist, not official Apple docs)
- UID 399 as safe unused UID for `_headscale` (A3 — convention, not guaranteed)
- macOS Gatekeeper quarantine xattr requirement (A5 — known macOS behavior, not Headscale-specific)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new deps; all implementation via stdlib + existing project code
- REST API endpoints: HIGH — confirmed from proto source + grpcv1.go source
- Policy mode behavior: HIGH — confirmed from source code (exact error string retrieved)
- cosign status: HIGH — confirmed from goreleaser.yml + release asset listing (finding: cosign absent)
- verify_client_url_fail_open: HIGH — confirmed this key does NOT exist in Headscale config
- macOS launchd non-root path: MEDIUM — man page confirms UserName works; port binding confirmed post-Mojave; UID selection and dscl idempotency are ASSUMED
- Architecture patterns: HIGH — mirrors existing tailscaleAdapter exactly

**Research date:** 2026-05-31
**Valid until:** 2026-08-31 (Headscale stable releases approximately quarterly; v0.29.0 may change endpoint behavior)

**Three items require user decision before planning commitment:**
1. cosign absence — SHA-256 only vs. wait for upstream
2. `verify_client_url_fail_open` does not exist — replace with `derp.server.verify_clients: true`
3. macOS launchd path risk — accept MEDIUM confidence or scope to Linux-only for Phase 12
