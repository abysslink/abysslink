# Abysslink Launch Runbook

This runbook documents the blocking gates and all post copy for the v4.0.0 public
launch. Complete the blocking gates in order before executing any post template.

---

## Blocking Gates

All four gates must pass before executing the §Post Templates section. These are
human-verified, operator-owned actions — no automated CI can claim them passed.

- [ ] **GATE-LNCH-02** (operator): Fresh macOS + Ubuntu VMs — run the quickstart end-to-end
      as an outside user, time it from `brew install abysslink` to `abysslink up --apply`
      success. **Must complete in < 10 minutes.** Record result and tester name below.

      Automated harness: `scripts/quickstart-firedrill.sh` times + asserts each step against
      the 600s budget.
      - Pre-check anywhere (safe, no mutation): `scripts/quickstart-firedrill.sh`
      - Real drill on a THROWAWAY fresh VM (mutating):
        `ABYSSLINK_FIREDRILL_I_UNDERSTAND=1 ABYSSLINK_EMAIL=you@example.com scripts/quickstart-firedrill.sh --apply`
      - Linux half, automated in a real fresh NixOS VM (needs Linux + KVM, i.e. CI):
        `nix build .#checks.x86_64-linux.quickstart-vm -L`
      The harness instruments the timing; the macOS fresh-VM + outsider requirement is still yours.

      Result: _______________ Tester: _______________ Date: _______________

- [ ] **GATE-LNCH-04** (operator): Claims audit final sign-off. Run
      `bash scripts/claims-check.sh` (must report 0 warnings). Read every row of
      `docs/claims-audit.md` and confirm each security sentence is honestly and accurately
      pointered. Sign: _______________ Date: _______________

- [ ] **GATE-LNCH-05** (operator): Physical-phone sovereign push test. Screen-off →
      notification arrives (UnifiedPush/ntfy path) → tap → tailnet-fetch → ack visible
      in `abysslink status`. Must run on real hardware (not simulator).
      Record device + OS: _______________ Date: _______________

- [ ] **GATE-LNCH-06** (operator): Install funnel verified. A published (non-draft)
      GitHub release with `.bundle` assets exists; `curl -fsSL .../install.sh | sh`
      succeeds on a clean macOS and a clean Linux machine; the `abysslink/homebrew-tap`
      repo exists and `brew tap abysslink/homebrew-tap && brew install abysslink`
      installs. (Context: the release pipeline has been red since v3.0.0 — only v1.0.0
      is published, without `.bundle` assets — and the tap repo does not exist yet.
      The install commands in every post template depend on this gate.)
      Result: _______________ Tester: _______________ Date: _______________

---

## Timing

- Post Tuesday–Thursday, 8–10 AM ET (peak Hacker News and Reddit traffic).
- 48h founder-response plan: monitor hourly for first 6h, then 3× daily for 48h.
- Have Show HN open in a tab, ready to submit. Do not submit until all four gates are
  checked.

---

## Operator Pre-Steps (before first release tag)

Complete these one-time setup actions before running `git tag v4.0.0`:

1. Create `abysslink/homebrew-tap` as a public GitHub repo (empty, no README required).
   goreleaser will write the cask `.rb` to it on release.

2. Add `HOMEBREW_TAP_GITHUB_TOKEN` as a GitHub Actions secret: a fine-grained PAT with
   `contents: write` on `abysslink/homebrew-tap` only. The default `GITHUB_TOKEN` is
   scoped to the main repo and cannot push to the tap.

3. Register `abysslink-bin` on AUR (one-time, requires an AUR account):
   ```sh
   ssh aur@aur.archlinux.org setup-repo abysslink-bin
   ```

4. Generate an ED25519 key pair for AUR:
   ```sh
   ssh-keygen -t ed25519 -f aur_key -N ""
   ```
   Register the public key at `aur.archlinux.org/account/<username>/` → SSH Keys.
   Add the private key as `AUR_SSH_PRIVATE_KEY` GitHub Actions secret (unencrypted,
   as required by goreleaser).

5. Enable GitHub Sponsors (optional, post-gates): see §GitHub Sponsors below.

---

## Post Templates

**DO NOT EXECUTE — These are reviewed templates only. Run after all blocking gates pass.**

---

### Show HN (`news.ycombinator.com/submit`)

**Title:** `Show HN: Abysslink – phone-to-laptop CLI that freezes runaway AI agents from your pocket`

**URL:** `https://github.com/abysslink/abysslink`

**Body:**

```
I built a CLI that lets you freeze a runaway AI agent from your phone.

The use case: you kick off Claude Code (or Aider, Codex, any agent) on your laptop,
step away, and something goes wrong — the agent is running in a loop, spending tokens,
eating disk state. Abysslink's kill-switch (we call it Apoptosis) wraps the run with
a git snapshot, a flight recorder, and wall-clock/loop budgets. It ships in shadow
mode by default — when a budget trips, your phone gets a notification. Enable the
full ladder (budget.ladder: true) and that trip freezes the agent with SIGSTOP;
from your phone you approve a resume or kill it outright, with optional rollback
of the working tree to the pre-arm git snapshot.

But the kill-switch is the headline; the rest of the tool is a phone-to-rig setup
that covers the boring-but-hard parts: one-command Tailscale + SSH + tmux + mosh
convergence, session-aware push notifications ("rig-1 · claude · %3 needs input")
that drop you straight into the right tmux pane, and a phone-approve loop for any
destructive command.

It runs on a private WireGuard mesh (Tailscale by default, or self-hosted Headscale /
NetBird). No public internet exposure. No third-party broker ever sees notification
content — push payload is routing metadata only; the body is fetched over the tailnet.

One static Go binary, macOS + Linux. Apache-2.0. Built end-to-end with Claude Code
(see docs/ai-story.md for the honest account). Supply chain: SLSA L3 via
actions/attest-build-provenance, cosign keyless signing, dual SBOM (SPDX + CycloneDX),
Grype + OpenVEX. No telemetry.

Quickstart: brew tap abysslink/homebrew-tap && brew install abysslink && abysslink up
Kill-switch demo: abysslink arm -- claude
Who sees what (push paths): docs/who-sees-what.md
```

---

### Lobsters (`lobste.rs/stories/new`)

**Tags:** `cli` `security` `go` `selfhosted`

**Title:** `Abysslink: a phone-to-laptop CLI that freezes runaway AI agents from your pocket`

**Note:** Disclose authorship per Lobsters norms — submit with the "authored by" checkbox ticked and open with "author here" in the first comment.

**Body:**

```
A Go CLI that sets up a paranoid-by-default phone-to-laptop remote-control stack
(Tailscale, SSH, tmux, mosh, self-hosted ntfy) and adds an AI agent kill-switch:
`abysslink arm -- claude` wraps the agent and monitors wall-clock and loop budget.
Shadow mode (the default) notifies your phone when a threshold trips; with the
ladder enabled (budget.ladder: true) the trip fires SIGSTOP — approve resume or
kill from your phone.

Security design: SLSA L3, cosign keyless, dual SBOM, audit log with HMAC chain,
push payload is metadata-only (content fetched over tailnet), ntfy bound to tailnet
IP only. Self-hosted Headscale and NetBird control planes supported. Apache-2.0.

Quickstart under 10 min on a fresh machine. Who-sees-what breakdown per push path
in docs/who-sees-what.md.
```

---

### r/selfhosted (`reddit.com/r/selfhosted`)

**Title:** `Abysslink — control your dev rig from your phone over Tailscale, with an AI agent kill-switch`

**Body:**

```
A CLI that automates the phone-to-rig setup I kept doing by hand: Tailscale (or
self-hosted Headscale / NetBird), hardened SSH, tmux + mosh, and a self-hosted ntfy
server bound exclusively to the tailnet IP — never 0.0.0.0, no Google, no Apple
dependency for the sovereign push path.

Push payload is routing metadata only; your phone fetches the real notification body
from the daemon over the tailnet. APNs / FCM / ntfy.sh never see content. Details:
docs/who-sees-what.md

Bonus feature: `abysslink arm -- claude` wraps an AI agent with a kill-switch. When
a budget threshold trips (wall-clock, command loops) your phone gets a notification —
that's the shadow-mode default. Enable the ladder (budget.ladder: true) and the trip
fires SIGSTOP: approve/kill from the dialog, optional rollback to the pre-arm git
snapshot.

One static Go binary. Apache-2.0. Quickstart under 10 min.
```

---

### r/ClaudeAI (`reddit.com/r/ClaudeAI`)

**Title:** `Control Claude Code from your phone — with a kill switch`

**Body:**

```
I built a tool that lets you drive Claude Code from your phone and freeze it when
it goes sideways.

The workflow: `abysslink arm -- claude` wraps the agent. When Claude stops or needs
input, your phone buzzes with the exact pane ("rig-1 · claude · %3 needs input") and
a tap drops you into the live tmux session. If it starts looping or running up the
wall-clock budget, your phone gets a warning (shadow mode is the default); with the
ladder enabled (budget.ladder: true) the kill-switch fires: SIGSTOP → approve/kill
dialog → optional rollback to the pre-arm git snapshot.

It's built on a private Tailscale mesh so the push notification body is fetched over
the tailnet, not through APNs/FCM. The opt-in Claude Code hook integration is a few
lines that wire Claude's Stop/Notification hooks into a generic notify module.

One static Go binary, macOS + Linux. Apache-2.0. Quickstart under 10 min.
```

---

### r/commandline (`reddit.com/r/commandline`)

**Title:** `Abysslink — one CLI to set up a Tailscale+SSH+tmux remote rig, with phone notifications and agent kill-switch`

**Body:**

```
A single static Go binary that converges your laptop into a phone-accessible remote
rig. CLI-first design:

- `abysslink up` is a dry-run convergence command (--apply to execute)
- `abysslink doctor` is a deep preflight checker that fails closed on unencrypted disk
- `--dry-run` is the default for every mutating op; explicit `--apply` required
- `abysslink arm -- <cmd>` wraps any long-running process with a phone kill-switch
  (shadow mode by default; full SIGSTOP ladder via budget.ladder: true)
- YAML config (strict schema; unknown keys rejected); TUI wizard via `abysslink init`
- `abysslink audit verify` checks the hash-chained tamper-evident audit log

CGO_ENABLED=0, -trimpath, reproducible builds, goreleaser + cosign + SLSA L3.
Apache-2.0. macOS + Linux.
```

---

### r/golang (`reddit.com/r/golang`)

**Title:** `Show /r/golang: Abysslink — a Go CLI with SLSA L3, cosign, dual SBOM, and a phone-to-rig notification stack`

**Body:**

```
A Go CLI that sets up a paranoid-by-default phone-to-laptop remote-access stack.
Some Go-specific things that might interest this community:

Supply chain: SLSA L3 via actions/attest-build-provenance, cosign keyless signing
(sign-blob with Sigstore's OIDC path), dual SBOM (Syft SPDX + CycloneDX), Grype +
OpenVEX. Reproducible builds (SOURCE_DATE_EPOCH from git, -trimpath, CGO_ENABLED=0).

Interesting patterns in the codebase:
- tsnet (Tailscale's Go library) for embedding a Tailscale node in-process
- bbolt as the outbox for the notification delivery guarantee
- shell.Runner with streaming stdout/stderr (every external command goes through it —
  no raw os/exec calls outside that package)
- audit.Writer: HMAC-chained log with optional ed25519 signing, zero secrets in the
  log body
- context.Context propagation throughout; cancellation in the convergence loop

Single binary (abysslink + abysslinkd daemon). Apache-2.0.
```

---

## GitHub Sponsors

`.github/FUNDING.yml` is committed. The "Sponsor" button will appear on the repo page
automatically once GitHub processes the file.

Sponsors program (payment processing) must be enabled separately by the org owner at
`github.com/sponsors/` — this is a manual GitHub UI action and is not triggered by
the FUNDING.yml commit alone.

Enable after gates pass and the first post goes live — not before. See
`.github/FUNDING.yml` for the file and its not-yet-enabled comment.

---

## Company-Interest Capture

Add to the docs site footer (or `docs/index.md`):

> Building something with Abysslink? We'd love to hear about it —
> [hello@abysslink.dev](mailto:hello@abysslink.dev)

Never "Enterprise — contact us" framing. Friendly and specific.

---

## 48h Founder Response Plan

- [ ] Monitor HN/Lobsters/Reddit hourly for first 6h after posting
- [ ] Respond to every top-level comment within 2h during the active window
- [ ] Pin a follow-up comment with install-troubleshooting link if > 5 support questions
      appear
- [ ] After 48h: write a brief retrospective note (what questions came up, what to
      improve in the quickstart)
