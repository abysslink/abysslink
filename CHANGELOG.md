# Changelog

Signed release notes with checksums live on [GitHub Releases](https://github.com/abysslink/abysslink/releases).

All notable changes to Abysslink are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.1.0] - 2026-07-12

### Added

- Quorum action gate: four deterministic verifiers vote before an irreversible agent
  action runs, any DENY vetoes, and a compiled deny-floor backstops them — no LLM, no
  network call in the decision path.
- Duress decoy (`abysslink duress`): a safe alternate unlock backed by argon2id keychain
  digests. Scoped honestly to casual coercion — it never wipes anything, and a test
  proves it.
- Sentinel: a high-precision detector for compromised-agent exfiltration attempts,
  layered onto the gated runner as defense in depth.
- Versioned HMAC key epochs for the audit log with in-chain rotation
  (`abysslink rotate audit-hmac`) and a matching `doctor` check.
- Signed, externally verifiable audit evidence bundles (`.alevidence`) with a published
  JSON Schema and `--json` output.
- Hardware-backed keys and local attestation.
- `abysslink diary`: a read-only end-of-day digest of the audit log.

### Changed

- In-memory secrets now live in mlock'd, zeroized buffers.
- `doctor` coverage extended across fleet and platform backlog checks.
- New fuzz targets for epoch-chain and evidence verification, plus performance-budget
  benchmarks for hot paths.
- Toolchain moved to Go 1.26.5; govulncheck runs clean.

### Fixed

- Audit verification no longer reports an unsigned post-counter append as benign lag.
- Five fail-open and honesty gaps closed in the merged audit-evidence surface.
- `verify` dropped a deprecated cosign flag.

## [4.0.1] - 2026-07-08

Repairs and ships the release that v4.0.0 held back. Preceded by two release-candidate
rehearsals (rc.1, rc.2) that proved the fixed signing path end to end.

### Added

- Typed Claude Code notifications: pushes distinguish approval, select, and input
  requests, carry a per-type emoji, and name the project in the title.
- Configurable notification `click_url` — tapping a push opens your saved host over its
  MagicDNS name; the init wizard prompts for it and the daemon reloads after apply.

### Fixed

- Release pipeline signing: cosign v4 installer, corrected attestation blob host, and
  the missing egress allowlist entries; package publishing now sits behind the
  sign-and-verify gate.
- `install.sh` fails closed when the cosign bundle is missing, and the checksum grep is
  anchored so SBOM lines no longer produce phantom mismatches.
- ntfy Docker port conflict when the tailnet IP changes on macOS; the container is also
  grouped under an "abysslink" folder in Docker Desktop.
- The mosh reachability step is flagged as sudo so its password prompt no longer races
  the progress spinner.

## [4.0.0] - 2026-07-02

*Tagged, not released.* The release run built and uploaded its artifacts, then failed in
the signing job (a cosign installer regression). Because publishing sits behind the
sign-and-verify gate, the pipeline refused to ship unsigned binaries and the release
stayed a draft — fail-closed working as designed. The fixed pipeline shipped this work
as v4.0.1.

### Added

- Phone approve loop: approve or deny the agent's next step from a push notification.
  It never auto-approves, every failure path denies, and tokens are 256-bit and
  single-use.
- Apoptosis kill-switch: `abysslink arm` runs an agent under a wall-clock and
  loop-detection budget with a shadow → SIGSTOP → kill ladder. Shadow mode is the
  default.
- Dead-man switch: an opt-in, daemon-hosted no-contact timer that triggers lockdown
  after operator silence (`abysslink deadman enable/status/heartbeat`), plus
  `doctor --profile at-risk` with tightened fail-closed floors.
- Session registry with needs-input detection: the daemon watches tmux panes and pushes
  "needs input" to your phone with zero manual steps; `notify` gains a wrap mode
  (`notify -- <cmd>`) that reports done or failed with honest exit codes.
- Push gateway and outbox with a tested policy engine: cooldown, flood ceiling with an
  honest meta-notification, bounded retry.
- Device SSH CA integration: sshd trusts device certificates via TrustedUserCAKeys and
  rejects revoked serials through an OpenSSH KRL, with drift surfaced by `doctor`.
- One-scan tailnet credential pull for phone enrollment, hardened against link-preview
  bots consuming or leaking the link.

### Changed

- Release pipeline lifted from SLSA Build L2 to L3: build and attest run in an isolated
  reusable workflow, and an attestation-verification gate blocks publishing.
  `verify` and `upgrade` fail closed on missing or invalid provenance.
- TUI overhaul: brand palette, reworked flows, OAuth handling, and hardening.
- `doctor` enforces external tool version floors (Tailscale and NetBird client FATAL,
  EternalTerminal WARN) and warns toward OpenSSH post-quantum key exchange.

### Fixed

- mosh-server reachability under Tailscale SSH.
- Daemon status reporting honesty; `make install` now installs abysslinkd.

## [3.0.2] - 2026-06-10

*Tagged, not released.*

### Added

- `abysslink init` rebuilt as a gated 8-stage wizard: per-stage confirmation, offers to
  run `up --apply`, Tailnet Lock init, phone enrollment, and `doctor` in place, a new
  ACL stage, and sudo routed through one interactive password prompt per run. Headless
  `--yes`/`--json` stays non-blocking.
- Manual-step prompts can re-copy the ACL snippet, and module manual steps wait until
  the TUI closes so they are never lost in scrollback.

### Fixed

- Adversarial sweep across the whole surface: keychain injection and HMAC-chain
  destruction paths, installer verification and script divergence, missing dry-run
  gates, dead flags and JSON exit codes, SSH checkPeriod bypass, broken notify probing,
  bind checks, and failed enrollment being reported as success.
- Nix build resolves with a real vendorHash and a pinned Go toolchain.
- Daemon shutdown detaches its context correctly, so shutdown work is no longer
  cancelled mid-flight.
- The sandbox module no longer fails `up` on macOS, and the apply summary is honest
  about what actually changed.

## [3.0.1] - 2026-06-04

*Tagged, not released.* Network and dependency security hotfix.

### Security

- ntfy binds to the tailnet only, enforced; NetBird server URLs must be https; argv
  injection guards on hostname and server URL inputs.
- Every attacker-influenceable read is now bounded, and binary installs stream to disk
  under a 256 MiB ceiling instead of loading whole files.
- Audit log hardening: backups are bound into the HMAC chain, every append is anchored
  with a keychain-held entry counter, writers take a cross-process lock, and counter
  verification is direction-aware to avoid false truncation alarms.
- Dependency floor raise: Go 1.26.4 toolchain, newer x/crypto, and CSRF protection
  migrated from gorilla to the standard library's CrossOriginProtection.
- `govulncheck` is a blocking CI gate; workflows are SHA-pinned and run under
  harden-runner.

### Changed

- `doctor` and `threat-model` share one findings set: fail-closed FATAL on unencrypted
  disk (exit 2), a minimum-versions table (ntfy ≥ 2.21 FATAL), and honest tri-state
  results when a probe itself fails.
- `config.Load` validates before returning, so a bad config fails closed; read-only
  commands like `rig ls` and `export` degrade gracefully.

## [3.0.0] - 2026-06-03

*Tagged, not released.* No v2.0.0 tag was cut — this tag ships two milestones together:
self-hosted backends and fleet (the v2 line) plus harden, observe and control (the v3
line).

### Added

- Self-hosted control planes: Headscale and NetBird backends behind a backend
  abstraction that fails closed on unknown types, with
  `abysslink server {headscale,netbird} init/status/upgrade/backup` and paranoid
  defaults (https-only, deny-all baseline).
- Multi-rig fleet: `enroll rig`, `rig ls/export/import`, and `--rig`/`--all-rigs`
  fan-out for status, doctor, notify, and panic — with HMAC rig-identity headers and
  unreachable rigs reported as results, not errors.
- Tamper-evident audit log: HMAC hash-chain appends, an anchor file, a chain verifier,
  and the `abysslink audit {verify,tail,ls,export}` surface.
- Supply chain: reproducible builds, dual SPDX/CycloneDX SBOMs, cosign v3 bundle
  signatures, the `abysslink verify` command, and a fail-closed installer.
- Observability: a dependency-free Prometheus `/metrics` listener bound to the tailnet
  IP only, daemon `GET /status`, the `abysslink report` posture snapshot, and a daily
  fleet digest.
- Optional read-only web UI as a separate build: TLS, Tailscale WhoIs authentication,
  CSRF protection, and its own FATAL doctor checks.
- 18 `sec-*` doctor checks plus `audit verify --pentest/--fix`; `threat-model` gains
  backend-aware rows.
- Wake-on-LAN: a `wol` command gated behind `--apply`.

### Changed

- Module hardening pass: Linux Landlock support in the sandbox module, atuin shell-rc
  changes written through the audit log, a hard warning floor on asciinema credential
  recording, and NetBird posture checks with an events tail.
- Lint gate extended with gosec, semgrep, and nolintlint; a gitleaks pre-commit hook and
  a fuzzing CI workflow guard the repo.

## [1.0.0] - 2026-05-28

First public release.

### Added

- Single-binary Go CLI that converges a hardened phone-to-laptop remote stack over
  Tailscale: `init`, `up` (dry-run by default, `--apply` to mutate), `status`, `doctor`,
  `repair`, `panic`, `enroll phone`, `notify`, `threat-model`, and `logs`.
- Eleven core modules — Tailscale (ACLs, Tailnet Lock), SSH hardening, tmux, mosh, ntfy
  push, power, and system hardening among them — plus optional modules: claudecode,
  code-server, ttyd, eternal-terminal, syncthing, atuin, upsnap, sandbox, and asciinema.
- Every file mutation goes through the audit log with an automatic backup; `uninstall`
  restores from those backups.
- The abysslinkd daemon, phone enrollment, and file and HTTP watchers.
- Secrets live in the OS keychain and never appear on argv.
- Signed releases via cosign keyless signing, a checksum-verifying `install.sh`, and
  `abysslink upgrade --apply` self-update.
- Release infrastructure: goreleaser pipeline, Nix flake, mkdocs documentation site, and
  a conformance harness.

[Unreleased]: https://github.com/abysslink/abysslink/compare/v4.1.0...HEAD
[4.1.0]: https://github.com/abysslink/abysslink/compare/v4.0.1...v4.1.0
[4.0.1]: https://github.com/abysslink/abysslink/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/abysslink/abysslink/compare/v3.0.2...v4.0.0
[3.0.2]: https://github.com/abysslink/abysslink/compare/v3.0.1...v3.0.2
[3.0.1]: https://github.com/abysslink/abysslink/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/abysslink/abysslink/compare/v1.0.0...v3.0.0
[1.0.0]: https://github.com/abysslink/abysslink/releases/tag/v1.0.0
