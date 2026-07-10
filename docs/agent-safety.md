# Agent Safety

Abysslink v4 ships five layers of agent containment: a phone approve loop for gating tool executions, a quorum-sensing action gate that decides *which* executions need that approval, an apoptosis kill-switch for runaway agents, a dead-man switch for operator absence, and one-tap panic. All of them ship in their safest *and least intrusive* configuration: the approve gate and the kill-switch ladder are **off (shadow / observe-only) by default** and are enabled explicitly in `abysslink.yaml`.

> **Honest severity:** these are safety nets, not guarantees. The approve loop gates agents that honor their hook contract (Claude Code hooks today); the kill-switch signals the armed process group. An agent running as your user that ignores hooks, escapes its process group, or has already exfiltrated credentials is outside their reach. For hard confinement, use OS-level sandboxing — these tools reduce blast radius and buy you reaction time.

## The phone approve loop

When `gate.enforcing: true` is set, tool executions are blocked until you approve them — from your phone or your terminal.

**Default is shadow mode.** `gate.enforcing` ships `false`: the exec gate observes and records (binary name + argv/closure hashes — never raw argv) but blocks nothing. Flip it to enforce:

```yaml
gate:
  enforcing: true        # default: false (shadow — observe only)
approval:
  timeout_seconds: 120   # default 120; valid 10–3600
  # extra_critical:      # optional: additional action-name substrings forced
  #   - "rm -rf"         # to the critical tier (add-only — can never loosen)
```

How a blocked action resolves (Claude Code wiring; `abysslink up --apply` writes the hooks into `~/.claude/settings.json` when enforcing):

1. Claude Code's `PreToolUse` hook runs `abysslink approve --check --blocking`, which opens a request on the daemon over its unix socket.
2. The daemon mints **single-use approve/deny capability URLs** (256-bit tokens, `ablk_ok_` / `ablk_no_` prefixed, HMAC-signed as defense-in-depth) and sends an `approval_request` notification with **Approve / Deny buttons**. Tapping a button hits the daemon's tailnet-only HTTPS listener; the token is consumed on first use.
3. In parallel, if a terminal is attached, you get a local prompt: `Abysslink: approve "Bash" tool call? [y/N]`. **First answer wins** — phone and TTY race for the same request; the daemon records exactly one decision.
4. The hook exits 0 (approved — the tool runs) or 2 (denied — Claude Code blocks the tool).

**It never auto-approves.** Every failure path resolves to deny: timeout after `approval.timeout_seconds`, daemon unreachable (5s dial timeout), headless with no phone answer — all exit 2. `approval_request` notifications are exempt from the notification cooldown and the per-device wake ceiling, so an approval is never silently dropped by rate limiting.

Requests carry a tier. Claude tool execs are *sensitive* (any approver: phone or TTY). Actions matching the built-in critical patterns (`panic-revoke`, `kill-switch-disarm`, `destructive-apply`) — plus anything you add via `approval.extra_critical` — are *critical* and **TTY-only** in v4; the phone cannot approve them. `extra_critical` can only tighten, never loosen.

## The quorum action gate

With an enforcing gate, *every* exec needs approval — safe but noisy. The quorum gate is the per-action policy that decides which execs are benign (proceed, audit-only), which need a human (escalate to the approve loop), and which are un-askable (deny outright). It ships **enabled** for evaluation and shadow auditing; enforcement rides `gate.enforcing` — the same single arm switch as the approve loop.

**Why a lattice, not a vote.** Knight–Leveson (1986) and its 2026 coding-agent replication showed that *agreement* among similar checkers is exactly the wrong-consensus trap: correlated checkers fail together. So the quorum never votes to allow. It combines four deterministic verifiers — independent in *input signal* — through a monotone security lattice `DENY > ESCALATE > ALLOW` using the meet (most-restrictive-wins):

| Verifier | Input signal | Catches | Fails on |
|---|---|---|---|
| V1 syntactic | raw argv token stream only | `rm -rf` (split flags too), force-push, `mkfs`/`dd`, `DROP TABLE`, pipe-to-shell, decode-and-exec | novel obfuscation |
| V2 policy | parsed intent + protected paths/branches policy | writes into `~/.ssh`, `/etc`, the audit-log dir, config/keychain/tailscale state; protected-branch force-push; `..`/glob/homoglyph ambiguity | parser gaps |
| V3 behavior | time + in-memory exec history only | destructive-op rate windows, global exec velocity, apply-without-prior-dry-run, spend threshold¹ | cold history (fails closed) |
| V4 reversibility | filesystem + VCS world state (read-only `git` probes) | deleting files with no undo (dirty tree, unpushed commits, no VCS) | stale cache / nonexistent targets |

¹ The spend-threshold rule is **not yet active** in the shipped daemon: no daemon-resident USD spend source is wired (`quorum.WithSpendFunc` is unset), so the rule is inert until one exists. Lowering `spend_threshold_usd` has no runtime effect today.

Rules, not models: **no LLM and no network call participate in the decision path** (enforced by source-invariant tests). The four verdict vectors are checked in CI for pairwise non-identity across a frozen adversarial corpus — independence is measured, not assumed.

How outcomes combine:

- **One DENY is a veto.** No combination of ALLOW votes can override it — ALLOW requires the *absence* of any DENY plus unanimous *confident* ALLOW.
- **Everything short of that escalates** to the existing phone/TTY approve loop at the demanded tier (sensitive: phone or TTY; critical: TTY-only in v4). A verifier error, timeout, panic, abstention, or low-confidence ALLOW escalates — never allows. Two or more verifier failures escalate at the critical tier.
- **A compiled-in deny-floor runs before the lattice and before any approval token**: Tailscale Funnel invocation, FileVault/LUKS disable, audit-log destruction, Tailnet-Lock disable, ntfy `0.0.0.0` bind, and canary tripwires deny without asking — a valid approval token does not bypass them, and no YAML key exists to remove or disable them (the Funnel-omission pattern). Unanimous garbage consensus on a floor action still denies.
- **Approval tokens are re-checked**: the closure hash is re-verified at exec time (TOCTOU), the token's tier must cover the computed tier, and the retry re-evaluates against *current* world state — a token can never launder a world that changed.
- **Unanswered escalations deny.** The approve loop's fail-closed timeout semantics are inherited unchanged: headless timeout denies, TTY timeout falls back to a terminal prompt, nothing auto-approves.

What the human sees on escalation is **dissent-first**: the notification leads with the strongest objection (e.g. `V4 reversibility: ESCALATE(critical) no-undo — unpushed commits · V1 syntactic: … · V2 policy: ALLOW · V3 behavior: ALLOW`) so the tiebreak reviews the objection, never a consensus summary. Titles and bodies carry rule codes, the binary basename, and protected-prefix *labels* — never raw argv, environment values, full paths, or capability URLs.

Every decision — enforcing *and* shadow — is appended to the hash-chained audit log as a full vote vector (`quorum-decision`, hash-only content), so a silently degrading always-ALLOW verifier is detectable from the log. Shadow mode is the day-one calibration corpus. Tripwire hits additionally append `quorum-tripwire` and fire an alert notification.

Configuration is **tighten-only** (see [configuration.md](configuration.md#quorum)): add-only protected paths/branches/patterns/canaries, lower-only spend threshold, raise-only tier overrides. Any loosening below the shipped defaults is a config *load error*. Disabling quorum under an enforcing gate falls back to approval-for-every-exec — strictly tighter, so the fallback can never loosen the gate.

Dry-run the policy anytime with `abysslink quorum eval -- <cmd>` (read-only; never executes), and verify the machinery with the `sec-quorum-*` doctor checks: a binary whose deny-floor no longer denies, whose adversarial self-test allows, or whose tripwires are disarmed is a FATAL doctor finding.

**Documented exemption (D-01a / KILL-03):** the quorum covers every exec that passes gate enforcement (`Run`, `RunWithStdin`, `RunInteractive`, `RunWithEnv`, `RunStream`). Armed long-running agent spawns (`RunArmed`/`RunArmedMinimal`, i.e. `abysslink arm`) are deliberately outside it — they are covered by the budget watcher below, which owns the whole process lifetime rather than a single exec event. The daemon's internal plumbing runner remains ungated (D-40).

## `abysslink arm` — the apoptosis kill-switch

Wrap any agent command to record it and watch it for runaway behavior:

```sh
abysslink arm -- claude                 # shadow mode: monitor + notify only
abysslink arm --apply -- claude         # also restore the working tree on exit
abysslink arm -- aider --model gpt-4o   # any long-running agent works
```

What arming does:

| Step | Mechanism |
|------|-----------|
| Git snapshot | `git rev-parse HEAD` + `git stash create` capture the arm-time working tree (nothing is modified) |
| Flight recorder | The command runs under `asciinema rec`; the cast lands in `~/.local/share/abysslink/casts/` and its SHA-256 is bound into the audit log at run end |
| Budget watch | Wall-clock limit (`wall_clock_minutes`, default 30) and loop detection (`loop_n`, default 8 identical command closure-hashes within a `loop_window` of 20 commands) |
| Registry | The armed process group is registered in `armed-runs.json` so the dead-man switch can find and disarm it |
| Rollback offer | On exit, the diff since arm time is always shown; `--apply` restores the arm-time tree (skipped with a warning if HEAD has advanced — no conflicting stash apply) |

**Shadow mode is the shipped default.** When a budget trips, the default behavior is a notification (`agent stopped: <reason>`) — the process is *not* stopped. The full escalation ladder is opt-in:

```yaml
budget:
  ladder: true             # default false (shadow). Enables SIGSTOP → phone Resume/Kill.
  wall_clock_minutes: 30   # default 30, floor 1
  loop_n: 8                # default 8, floor 2
  loop_window: 20          # default 20, floor 5
  kill_grace_seconds: 5    # SIGTERM→SIGKILL grace, default 5, valid 1–30
  # minimize_agent_env: true      # opt-in: spawn the agent with a minimal env
  # token_tiers:                  # opt-in token-spend observation
  #   jsonl_path: ~/.claude/projects/.../session.jsonl
  #   warn_tokens: 500000
  #   stop_tokens: 1000000
```

With `ladder: true`, a tripped budget sends **SIGSTOP** to the agent's process group and opens a phone approve request (Resume / Kill). Approve sends SIGCONT and re-arms the watcher; deny sends SIGTERM, waits `kill_grace_seconds`, then SIGKILL. On timeout the process **stays frozen and you are re-notified — the ladder never auto-decides**.

Missing prerequisites degrade gracefully, never block arming: no `asciinema` disables the recorder, no `git` disables snapshot/rollback, no keychain disables the capability-URL HMAC signatures. The one hard refusal: `arm` will not spawn an agent while a dead-man lockdown is active (and it fails closed if the lockdown state cannot be read).

## The dead-man switch

Opt-in (ships off): a daemon-hosted no-contact timer that fires a lockdown after N hours of operator silence.

```sh
abysslink deadman enable --apply                    # 24h default interval
abysslink deadman enable --interval-hours 12 --apply
abysslink deadman heartbeat                         # reset the no-contact deadline
abysslink deadman status                            # enabled? interval? time remaining?
```

- `enable` is dry-run by default; `--apply` persists `deadman.enabled: true` to `abysslink.yaml` (interval floor 1h; 0 means the 24h default). Enabling seeds the contact clock, so the countdown starts immediately.
- `heartbeat` is the contact signal; the reset is audit-written.
- The timer is hosted by `abysslinkd` and is **restart-safe** — the last-contact deadline persists across daemon restarts.

When the deadline elapses, lockdown fires with a deliberately narrow scope: it disarms every registered armed run (SIGTERM → grace → SIGKILL on the process group), sets a lockdown flag that makes `abysslink arm` refuse to start new agents, and audit-logs the event. It **never** touches the SSH CA, device credentials, or the network — too destructive for an automated timer. After investigating, clear the lockdown by removing the flag file (`deadman-lockdown.json` under `~/.local/state/abysslink/`).

## `abysslink panic`

The emergency kill switch. Executes immediately, **no confirmation prompt**:

1. Disconnects the machine from the tailnet.
2. Revokes phone devices carrying your mobile tag (requires admin-API credentials; otherwise prints manual steps).
3. Revokes every enrolled device credential — bearer, push token, SSH certificate.
4. Destroys the local Anthropic API key from the keychain (including rig-scoped copies).

Every step is best-effort and audited; a failed step prints ✕ and panic continues. It is reversible: `abysslink repair --apply` reconnects, `abysslink enroll phone --apply` re-mints device credentials. `--rig <name>` panics one enrolled rig; `--all-rigs` fans out to the fleet after securing the local machine. Panic cannot revoke the API key server-side — do that in the Anthropic console (it tells you).

## Device credential lifecycle

Phone credentials are minted, listed, and revoked per device:

```sh
abysslink enroll phone --apply    # mint: bearer + push token + short-lived SSH cert
abysslink device ls               # list devices, cert expiry, last-seen, stale flag
abysslink device revoke phone     # dry-run preview
abysslink device revoke phone --apply
abysslink device ca               # print the device SSH CA public key
```

- Certificates are minted by an in-process ed25519 **SSH CA whose private key lives only in the OS keychain**. The bearer is stored as a SHA-256 hash; the plaintext exists only in the one-time enrollment bundle — never on disk, never logged.
- `revoke --apply` blanks the device's bearer hash and push token and records the certificate serial in the revocation list; the next `abysslink up --apply` rebuilds the OpenSSH **KRL** (`/etc/ssh/abysslink.krl`) so `sshd` rejects the revoked cert. `device ca` prints the CA line for `TrustedUserCAKeys` (wired automatically on OpenSSH-fallback rigs).
- `device ls` flags a device **stale** after 7 days without contact — a prompt to revoke what you no longer use.

Every mutation of the device store goes through the audit chain (backup + hash-only entry, mode 0600).

## Related pages

- [Push notifications](push-notifications.md) — the opaque-wake payload rule and how approval buttons reach your phone.
- [Threat model](security/threat-model.md) and [Who sees what](who-sees-what.md).
- [Configuration reference](configuration.md) — the `gate`, `approval`, `quorum`, `budget`, and `deadman` keys.
