# CI fire-drill (LNCH-02) — automated quickstart timing

This is how the LNCH-02 quickstart fire-drill runs in CI, and how credentials are handled.

## TL;DR — credentials are CI-only, never committed

- You add secrets in **repo → Settings → Secrets and variables → Actions**.
- The workflow references them by name (`${{ secrets.TS_AUTHKEY }}`); they are injected as
  **environment variables at runtime** and scrubbed from logs.
- **Nothing secret is ever committed**, put on argv, or written to disk. This matches the
  project hard rules (`CLAUDE.md`: no secrets on argv, no secrets in repo) and how Phase 32
  already handles `HOMEBREW_TAP_GITHUB_TOKEN` / `AUR_SSH_PRIVATE_KEY`.
- **Do not paste a key into a chat, PR, or issue.** Put it straight into GitHub Secrets.

## The two jobs (`.github/workflows/firedrill.yml`)

### 1. `nix-dryrun-vm` — verified, always safe

Runs the dry-run drill inside a **real fresh NixOS VM** (`nix build .#checks.x86_64-linux.quickstart-vm`):
binary smoke, `up --dry-run` plan (no mutation), `doctor` read-only health, command-surface
asserts. No secrets, no persistent mutation. Also runs `nix build .#abysslink` to guard the
flake build (the stale-`vendorHash` regression that broke "build from the flake").

Triggers: weekly schedule + manual dispatch. This is the part that is **verified to run**.

### 2. `ubuntu-apply` — the real mutating drill (EXPERIMENTAL)

Runs the real `init → up --apply → doctor → enroll` flow on an **ephemeral Ubuntu runner**
(a genuine throwaway Ubuntu VM, with `apt`). Manual dispatch only, and only when `TS_AUTHKEY`
is set — so it never blocks normal CI.

> **Status: experimental.** `up --apply` converges a whole hardened rig (sshd hardening, ntfy
> bind, mosh, power, keychain). Each leg may need handling on a GitHub runner. Expect to iterate
> on your CI before this job is green — it was authored against the source, not yet run to green.

## Credentials per backend (env var names verified in source)

| Backend (config `tailnet.backend`) | Secret you set | Env var the code reads | Source |
|---|---|---|---|
| **tailscale** (default) — node auth | Tailscale **ephemeral, pre-authorized, tagged** auth key | `TS_AUTHKEY` (used to pre-auth the node via native `tailscale up`; abysslink's default `Up` does **not** inject a key) | `internal/backend/tailscale.go` |
| **tailscale** — admin API (ACL push, device mgmt) | OAuth client **secret** (client **ID** goes in `abysslink.yaml` `tailnet.admin.oauth_client_id`) | `ABYSSLINK_TS_OAUTH_SECRET` | `internal/backend/tailscale.go:30` |
| **headscale** | pre-auth key | `ABYSSLINK_HS_PREAUTHKEY` (injected as `TS_AUTHKEY` to `tailscale up` via `RunWithEnv`, never argv) | `internal/backend/headscale.go:41,283` |
| **netbird** | setup key / API key | `ABYSSLINK_NB_SETUP_KEY` / `ABYSSLINK_NB_API_KEY` | `internal/backend/netbird.go:37,41` |

Generate the Tailscale auth key in the admin console (**Settings → Keys**): **ephemeral**
(node auto-removes when the runner dies), **pre-authorized**, **tagged** (ACL-scoped), short
expiry, ideally single-use.

## Why a loopback-LUKS fixture

`up --apply` is **fail-closed on disk encryption** — it refuses unless
`platform.DiskEncryptionStatus` returns `DiskEncrypted`, and there is **no bypass** (not even
`--force-unsafe`). On Linux that check runs `lsblk -J -o NAME,TYPE` and passes when **any**
block device has `TYPE=crypt` (`internal/platform/linux/platform.go` `hasCryptDevice`).

A GitHub Ubuntu runner's disk is not encrypted, so the `ubuntu-apply` job creates a small
**loopback LUKS device** (`cryptsetup luksFormat` on a 64 MiB file → `luksOpen`) so a real
`crypt` device exists. This is a **CI test fixture** — a real fresh VM would boot from a LUKS
root. It does not weaken the gate (a genuine LUKS device is present); it makes the gate
satisfiable in an ephemeral runner.

## Running it

```sh
# From the GitHub UI: Actions → firedrill → Run workflow.
# Or with the CLI:
gh workflow run firedrill.yml
```

- Without `TS_AUTHKEY`: only `nix-dryrun-vm` does meaningful work; `ubuntu-apply` skips the
  mutating drill with a notice.
- With `TS_AUTHKEY` (+ optional `ABYSSLINK_TS_OAUTH_SECRET`): `ubuntu-apply` runs the real
  timed `--apply` drill and fails if it exceeds the 600 s LNCH-02 budget.

## What stays manual (cannot be automated here)

- **macOS half of LNCH-02** — no macOS VM in Nix or on Linux CI. A human runs the quickstart on
  a fresh Mac and times it (`scripts/quickstart-firedrill.sh --apply` on a throwaway Mac).
- **The "outsider" requirement** — the gate is about a *new user's* experience; automation
  measures timing, not first-time comprehension.

## Local pre-check (no VM, no secrets)

```sh
scripts/quickstart-firedrill.sh        # dry-run, read-only, safe anywhere
```
