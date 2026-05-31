# Phase 12: Headscale Backend - Context

**Gathered:** 2026-05-31
**Status:** Ready for planning
**Milestone:** v2.0.0 — Self-Hosted Backends & Fleet

<domain>
## Phase Boundary

Implement the full Headscale backend behind the existing `internal/backend.Client`
seam built in Phase 11. Three requirement clusters:

- **HS-01 — Client adapter:** point the client at a Headscale login server
  (`backend.type: headscale`), enroll a node, push a deny-all baseline HuJSON ACL
  via the reused v1 parser before the first node is admitted, report
  `Caps().Lock = false`.
- **HS-02 — Server provisioning (full):** `abysslink server headscale
  init/status/upgrade/backup` — cosign-verified binary, hardened `config.yaml`
  (TLS gate, `verify_client_url_fail_open: false`, embedded DERP), non-root
  service, pre-auth keys always with explicit short RFC3339 expiry, SQLite DB
  included in `abysslink backup`.
- **HS-03 — Doctor checks:** all nine `hs-*` checks report correct PASS/WARN/FAIL.

This phase plugs a new backend into the Phase 11 seam. It must not weaken any v1
default and must not leak Headscale logic into ssh/tmux/mosh/notify/watch.
Tailnet Lock (TKA) does not exist on Headscale → `hs-lock` is a permanent WARN,
never PASS.

</domain>

<decisions>
## Implementation Decisions

### Server provisioning model
- **D-01:** Provisioning is **local-host-only**. `abysslink server headscale
  init --apply` must run ON the box that becomes the control plane; it writes the
  binary, `config.yaml`, and the service unit locally through `internal/audit`
  (backup + audit-log on every mutation). Remote control = run abysslink on that
  box via the user's existing SSH. No abysslink-managed remote/over-SSH transport
  in this phase. Matches the v1 local-mutation-only pattern.
- **D-02:** Server provisioning is supported on **both Linux (systemd) and macOS
  (launchd)**. This is a deliberate extension beyond the ROADMAP's `systemd unit`
  wording — see **Deviation note** below. The non-root floor is honored on both:
  Linux runs `User=headscale`; macOS runs under a dedicated non-login service
  account via a launchd plist. Research must define the macOS service-account
  creation + launchd plist path (no upstream precedent — verify carefully).
- **D-03:** `config.yaml` is managed by **surgical merge**, mirroring the Phase 5
  HuJSON ACL-editor pattern. abysslink ensures the required hardened keys are
  present/correct (TLS gate, `verify_client_url_fail_open: false`, embedded DERP,
  `policy.mode: database`, DB path) but preserves the user's other
  customizations. `init`/`up` re-runs are idempotent. Not full-template
  ownership.
- **D-04:** `abysslink server headscale upgrade` = **cosign-verify → backup DB →
  swap**. Verify the new binary signature (same cosign gate as `init`),
  `abysslink backup` the SQLite DB first, stop the service, swap the binary,
  restart, health-check. **Refuses downgrade.** Honors the v1 "backup on every
  mutation" floor.

### TLS cert strategy
- **D-05:** **BYO-verify is the default; `--acme` (ACME/Let's Encrypt) is an
  explicit opt-in.** The TLS gate refuses to proceed in either mode without a
  valid cert.
- **D-06:** BYO validity is **strict / fail-closed**: cert not expired (and not
  within N days of expiry), CN/SAN matches the `server_url` FQDN, parses as a
  valid chain, and key-file perms are tight (0600, owned by the service user).
  Any miss → refuse.
- **D-07:** When `--acme` is used, the topology is **Headscale-native, no reverse
  proxy** — Headscale owns 443 and co-hosts HTTPS API + DERP over a single TLS
  listener using its built-in ACME. No Caddy/nginx provisioned by abysslink.
  Research MUST confirm Headscale can cleanly co-host DERP + API + ACME on one
  cert/listener and resolve the port-80/443 interaction (see Research Flags).

### Admin API transport
- **D-08:** The client adapter performs **all** admin ops (device list/tag/delete,
  auth-key create, ACL get/set) via **net/http to the Headscale gRPC-gateway REST
  API (`/api/v1/...`) with a Bearer API key**. Works remotely, needs no local
  socket, and matches the `AdminAPI` / `ACLManager` sub-interfaces + the v1
  admin-over-HTTP shape. No shelling the `headscale` CLI from the client adapter.
- **D-09:** Server provisioning **enforces `policy.mode: database`** (set via the
  surgical config merge) so REST `SetACL`/`GetACL` and the deny-all baseline
  actually take effect. A doctor check FAILs if a Headscale backend is in
  file-mode (REST ACL pushes would silently no-op). File-mode is not supported in
  this phase.
- **D-10:** The Headscale **API key lives in the OS keychain** (env/stdin fallback
  on first set), same secret path as v1 ntfy/Tailscale-admin creds. A co-located
  server provisioner mints one via `POST /api/v1/apikey` REST call (short expiry)
  and stashes it. **Never on argv, never in the audit log.**

### Enrollment / pre-auth key handoff
- **D-11:** At `up`, the client obtains + consumes the **pre-auth key via
  keychain (or stdin pipe on first set)**, then registers reading the key from
  stdin/env (`--authkey=-` style) — **never on argv**. If abysslink also runs the
  server locally, it mints the short-expiry pre-auth key and stashes it
  automatically. Not interactive `nodes register`, not OIDC-browser as the
  primary path.
- **D-12:** `hs-oidc-filter` semantics: **PASS/SKIP when OIDC is not configured**
  (pre-auth-key-only deployments have no open-registration vector). The check
  FAILs **only** when OIDC IS enabled AND `allowed_domains`/`allowed_users` is
  empty. Targets the real footgun (open OIDC), not the absence of OIDC.
- **D-13 (Claude's Discretion — resolved 2026-05-31):** During `abysslink server
  headscale init --apply`, abysslink ensures a Headscale **user exists before
  minting any pre-auth key**. The user is created idempotently (check-then-create):
  call `GET /api/v1/user` to list users; if a user named `abysslink` does not
  exist, call `POST /api/v1/user` to create it. The stable default user name is
  **`abysslink`** (not derived from the email local-part — fixed name is simpler,
  predictable across re-inits, and not PII). This user name is stored in
  `cfg.Server.Headscale.User` (already a field in the HeadscaleServer struct from
  Plan 12-01) so operators can override it. Pre-auth keys (`POST /api/v1/preauthkey`)
  and the deny-all baseline are created under this user. Both REST calls use the
  same `doRequest` pattern (D-08). The init sequence order is: TLS gate → binary
  download/verify → version floor check → config merge → user ensure (D-13) →
  API key mint → pre-auth key mint → service install.

### abysslink init wizard extension
- **SC-1:** The existing `abysslink init` wizard (`internal/cli/cmd_init.go`
  `runInitForm`) is extended to offer `backend.type: headscale` as a choice
  alongside the default Tailscale backend. When the user selects `headscale`, the
  wizard additionally prompts for `backend.headscale.server_url`. This is
  implemented in Plan 12-05 and does not affect the default Tailscale path.

### Claude's Discretion
- Exact `N`-days-before-expiry threshold for the strict cert check (D-06) and for
  pre-auth-key "short expiry" (pick a paranoid-sane default; document it).
- Internal package layout for the Headscale adapter under `internal/backend/`
  (follow the Phase 11 Tailscale-adapter precedent).
- Doctor-finding wording for each `hs-*` check (keep the `hs-lock` WARN text
  exactly as the ROADMAP specifies).
- Headscale user name for pre-auth keys: **`abysslink`** (per D-13 above).

### Research Resolutions (2026-05-31, user-confirmed post-research)
These OVERRIDE the original spec wording where they conflict. Planner must honor.
- **R-01 (supersedes "cosign" in D-04 / ROADMAP SC-2):** Headscale publishes NO
  cosign signatures (verified v0.28.0 `.goreleaser.yml`) — only `checksums.txt`
  SHA-256. Binary gate for `init`/`upgrade` = **SHA-256 verified against
  `checksums.txt` fetched over TLS from the GitHub release, with the expected
  per-version hash PINNED in abysslink source**. Fail closed on mismatch.
  Document cosign as a future upgrade when upstream adds it. The doctor/verify
  wording must say "checksum-verified", not "cosign-verified".
- **R-02 (supersedes `verify_client_url_fail_open: false` in D-07 / ROADMAP SC-2):**
  That key does NOT exist in Headscale (it's a standalone `derper` flag). The
  hardened `config.yaml` key set and the `hs-derp-failclosed` check use the real
  embedded-DERP key **`derp.server.verify_clients: true`** (default true; assert it
  is not disabled). Same security intent, correct key.
- **R-03 (confirms D-02 macOS scope):** macOS launchd provisioning STAYS in Phase
  12 (Linux/systemd + macOS/launchd together). Research = feasible/MEDIUM, no
  upstream precedent for the `dscl` service-account creation. Planner MUST gate the
  macOS service-account + launchd-plist task with `checkpoint:human-verify` so the
  MEDIUM-confidence path is reviewed at execution, not silently shipped.
- **Pinned version floor:** minimum supported Headscale **v0.23.0** (DB-mode policy
  + policy REST API introduced); current stable **v0.28.0**. Pin a concrete tested
  version in the binary download/verify path.

### Deviation note (must surface to planner)
ROADMAP HS-02 / Success Criterion 2 says the server runs as a **systemd unit
(`User=headscale`)**. D-02 extends provisioning to **macOS via launchd** as well.
This is a user-approved scope addition, not a relitigation of the non-root floor
(which still holds on both OSes). Planner should treat macOS-launchd as in-scope
for Phase 12 and size it accordingly; if research finds the macOS path materially
risky, flag back to the user before committing it to plans.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

> **Note:** the load-bearing planning specs live under `.mine/docs/` (private,
> gitignored). CLAUDE.md refers to them as `docs/…` as shorthand — use the
> `.mine/docs/` copies.

### Phase spec (de-facto — no SPEC.md exists)
- `.planning/ROADMAP.md` §"Phase 12: Headscale Backend" (lines ~243–256) — goal +
  5 success criteria. The authoritative spec for this phase.
- `.planning/REQUIREMENTS.md` — **HS-01, HS-02, HS-03** definitions (lines
  ~251–253). The requirement source.
- `.planning/PROJECT.md` §"Current Milestone: v2.0.0" — immutable floors carried
  from v1; backend logic must not leak into ssh/tmux/mosh/notify/watch.

### Security model & conventions (must not weaken)
- `.mine/docs/DESIGN.md` — §0/§2.0/§4/§6/§7 load-bearing security model; §10 repo
  layout (where `internal/backend` lives).
- `.mine/docs/IMPLEMENTATION-TASKS.md` — Conventions + cross-cutting decisions not
  to relitigate.
- `CLAUDE.md` — Hard rules: all exec via `shell.Runner`, all file mutation via
  `internal/audit`, no `sh -c`, no secrets on argv, no secrets in audit log,
  `--dry-run` default, `context.Context` everywhere, Apache-2.0 header per file.
- `.mine/docs/ROADMAP-ECOSYSTEM.md` — post-v1 ecosystem context (forward-compat).

### Phase 11 seam (the interface this backend plugs into — read in full)
- `.planning/phases/11-backend-abstraction-refactor/11-CONTEXT.md` — adapter
  pattern, Core `Client` + optional sub-interfaces (`Locker`/`AdminAPI`/
  `ACLManager`), capability-gate WARN-skip + `ErrUnsupported`, the
  `Capabilities.X == true ⟺ adapter implements sub-interface` invariant.
- `internal/backend/client.go` — `Client`, `Locker`, `AdminAPI`, `ACLManager`,
  `ACLEditor` interfaces (the method sets the Headscale adapter must satisfy).
- `internal/backend/factory.go` — `New(cfg, runner)` switch; add the
  `case "headscale"` here (fails closed on unknown type today).
- `internal/backend/capabilities.go`, `types.go` — `Capabilities` struct + neutral
  types; Headscale sets `Lock = false`.
- `internal/backend/tailscale.go` + `contract_test.go` + `invariant_test.go` —
  precedent for a new adapter and its contract/invariant tests.

### Existing code to wire into / reuse
- `internal/config/config.go` — `Backend{Type}`, `Server{Hostname}` stanzas
  (lines ~44–55) already parse; extend `Server` for Headscale provisioning fields
  (TLS paths, ACME toggle, DB path) under strict-mode YAML.
- `internal/cli/cmd_doctor.go` — `doctorFinding` shape + `modules.Finding`
  pipeline; the nine `hs-*` checks emit through this.
- `internal/cli/cmd_acl.go`, `internal/modules/acl/` — HuJSON ACL editor + push
  flow to reuse for the deny-all baseline (HS-01).
- `internal/cli/cmd_lock.go` — print-once secret + keychain pattern to mirror for
  the API key / pre-auth key (D-10, D-11).
- `internal/cli/cmd_upgrade.go` — existing cosign-verified binary upgrade pattern
  to reuse for `server headscale upgrade` (D-04).
- `internal/cli/cmd_backup.go` + `internal/audit` — backup/restore manifest;
  SQLite DB joins this for `server headscale backup` (HS-02).
- `internal/shell.MockRunner` + `httptest` — hermetic mock Headscale REST API
  fixtures (Success Criterion 5).
- `internal/cli/cmd_init.go` `runInitForm` — wizard extended in Plan 12-05 to
  offer `backend.type: headscale` + `server_url` prompt (SC-1 / D-13).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **HuJSON ACL editor** (`internal/modules/acl/`, `internal/cli/cmd_acl.go`):
  reuse the v1 parser/editor to build + push the deny-all baseline (HS-01).
- **Keychain secret path** (`cmd_lock.go` print-once + keychain): mirror for the
  Headscale API key and pre-auth key (D-10, D-11) — never on argv/audit.
- **cosign upgrade** (`cmd_upgrade.go`): same signature-verify gate for the
  Headscale binary download (`init`) and `upgrade` (D-04).
- **audit backup/restore** (`internal/audit`, `cmd_backup.go`): SQLite DB joins
  the backup manifest; config.yaml/unit writes go through audit.
- **MockRunner + httptest**: hermetic REST-API fixtures for tests.

### Established Patterns
- **Adapter + sub-interface + WARN-skip** (Phase 11): Headscale adapter implements
  `Client` + `AdminAPI` + `ACLManager`, NOT `Locker`; sets `Capabilities.Lock =
  false`. Lock-gated modules WARN-skip (no plan entry) — already wired in Phase 11.
- **No-concrete-import build guard** (depguard, Phase 11): modules/CLI consume only
  `internal/backend`; the Headscale adapter lives inside the package.
- **Factory fails closed**: add `case "headscale"` to `backend.New`; unknown types
  still error.
- **Surgical-merge config editing** (ACL-editor precedent) extends to `config.yaml`
  (D-03).

### Integration Points
- `backend.New` factory switch (`factory.go`) — new `headscale` case.
- `config.Server` stanza — Headscale provisioning fields.
- `cmd_doctor` finding pipeline — nine `hs-*` checks.
- New `abysslink server headscale …` command subtree under `internal/cli/`
  (no `server` command exists yet — greenfield CLI surface).

</code_context>

<specifics>
## Specific Ideas

- `hs-key-expiry` closes the upstream Headscale issue **#1579** vector — assert a
  non-zero expiry in every pre-auth-key API response; FAIL if any active key has
  no expiry.
- `hs-lock` WARN text is fixed by ROADMAP: `WARN: server-trust model only —
  Tailnet Lock (TKA) is not available on Headscale`.
- Nine checks (exact names): `hs-tls`, `hs-bind`, `hs-api-auth`, `hs-key-expiry`,
  `hs-db-perms`, `hs-lock`, `hs-oidc-filter`, `hs-proc-user`, `hs-derp-failclosed`.
- Deny-all baseline must be pushed **before the first node is admitted** (ordering
  constraint in Success Criterion 1).

## Research Flags (open questions for the researcher)

1. **ACME + embedded DERP on one listener** (D-07; STATE.md MEDIUM-confidence
   blocker): confirm Headscale can co-host HTTPS API + DERP + built-in ACME on a
   single 443 cert/listener; resolve HTTP-01 (port 80) vs TLS-ALPN; document the
   exact `config.yaml` keys.
2. **macOS launchd server path** (D-02): define service-account creation + launchd
   plist for a non-root Headscale on darwin; verify the binary runs cleanly. No
   upstream precedent — assess risk and flag if material.
3. **Headscale REST API coverage** (D-08): confirm `/api/v1/...` gRPC-gateway
   endpoints cover device list/tag/delete, apikeys create, preauthkeys create
   (with expiry), and policy get/set in DB-mode across the target Headscale
   version. Identify the minimum supported version; pin it.
4. **`policy.mode: database` behavior** (D-09): confirm DB-mode HuJSON push/read
   semantics and how to detect file-mode for the doctor FAIL.
5. **`hs-db-perms` / `hs-bind` / `hs-proc-user` concrete checks**: define exact
   SQLite DB file perms, the loopback/overlay-IP bind assertion, and the process
   service-user assertion on both Linux and macOS.

</specifics>

<deferred>
## Deferred Ideas

- **Reverse-proxy (Caddy/nginx) TLS termination** — rejected for this phase in
  favor of Headscale-native (D-07). Revisit only if research proves native ACME +
  DERP co-hosting unworkable.
- **OIDC as the primary enrollment path** — pre-auth-key is primary (D-11). OIDC
  support beyond the `hs-oidc-filter` defensive check is out of scope here.
- **Remote/over-SSH server provisioning** — explicitly out of scope (D-01).
- **File-mode ACL policy support** — out of scope; DB-mode enforced (D-09).
- **Headscale PostgreSQL HA** — already deferred to v2.x (STATE.md). SQLite only
  in this phase.
- **NetBird backend** — Phase 13. **Multi-rig fleet** — Phase 14.

</deferred>

---

*Phase: 12-headscale-backend*
*Context gathered: 2026-05-31*
*Context revised: 2026-05-31 (added D-13, SC-1 wizard extension)*
