# Why Abysslink

Remotely controlling a development rig from a phone is not a new idea. Several tools and approaches already exist. Here is an honest look at how Abysslink compares and where it fits.

## Prior Art

| Tool | What it does | Why we built something different |
|---|---|---|
| **Moshi** | Real-time voice and video AI assistant; lets you speak to a model that can see and hear | Different problem — Moshi is about conversational input modality, not remote shell control or session management. No persistent tmux session, no push-when-idle loop, no tailnet. |
| **Claude Code Channels / claude-push** | Push notifications from Claude agents to a phone or channel | Covers the notification leg only. No phone-approve loop, no agent kill-switch, no Tailscale-native session awareness, no tamper-evident audit chain. Great building block; Abysslink uses the same idea but embeds it into a full secure-remote-access stack. |
| **ntfy** | Sovereign self-hosted push notifications; clients subscribe to topics | Abysslink uses ntfy as one of its push transport backends. On top of ntfy, Abysslink adds: session-typed metadata (rig + agent + pane identity), opaque-payload fetch-over-tailnet (brokers never see body), phone approve loop tied to an execution-closure hash, and the full enroll/revoke lifecycle. |
| **Tailscale SSH** | Tailscale-native SSH access without port exposure; key exchange via control plane | Abysslink wraps Tailscale SSH and adds: the push-notification and approve loop, the agent kill-switch (Apoptosis), a hardened `sshd_config` with `checkPeriod` enforcement, mosh for roaming resilience, tmux for session persistence, and `abysslink doctor` fail-closed checks for every footgun Tailscale SSH leaves as a user responsibility. |

## What Abysslink adds

- **Paranoid-by-default automation.** One command (`abysslink up --apply`) enforces every safety check the original 7-file setup guide documented manually: Tailscale Funnel rejected at the schema, ntfy bound to tailnet-IP only, SSH `checkPeriod` floor enforced, disk encryption required.
- **Session-aware typed notifications.** Every push names the exact rig, agent, and pane that needs you (`rig-1 · claude · %3 needs input`). A tap drops you back into that live tmux session — not a generic "something happened" alert.
- **Phone approve loop.** High-risk agent actions require an explicit tap-to-approve on the phone. The approve token is bound to an execution-closure hash, so replaying a stale approval does nothing.
- **Agent kill-switch (Apoptosis).** Freeze or abort a runaway agent from your phone. Ships in shadow mode by default — it observes and logs without interrupting until you arm it explicitly.
- **Tamper-evident audit chain.** Every file mutation is backed up and appended to a hash-chained audit log. Verify with `abysslink audit verify`; undo anything with `abysslink backup restore`.
- **SLSA L3 attested releases.** Every release carries a cosign-signed checksum manifest and a GitHub-attested SLSA L3 provenance bundle. `abysslink verify` and `abysslink upgrade` refuse to install without them.

## What Abysslink does not do (yet)

- **No native mobile app (v5, separate repo).** The phone side is a standard terminal app (Blink, Termius, Termux) plus the ntfy app for push. A dedicated iOS/Android app with richer approve UI is planned for v5 in a separate repository.
- **No proprietary cloud relay.** Content never leaves your tailnet. The push payload is routing metadata only; the phone fetches the actual body from your daemon over the encrypted tailnet link.
- **No telemetry.** The binary makes no outbound calls except to your VPN's local API and your own ntfy server.

See the [quickstart](quickstart.md) to get running in under ten minutes, or the [security](security.md) page for the full threat model and hardening guide.
