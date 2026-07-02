# Push Notifications

How a notification actually travels from your rig to your phone in v4: the daemon sends an **opaque wake** through a push gateway, and your phone fetches the content over the tailnet afterwards. No broker ever holds the body.

## The payload rule

The v2 notification schema (`internal/notifyv2`) carries **routing metadata only**. The `Message` type has no body field *by construction* — it carries a msg ULID, host name, tmux session/window/pane reference, kind, a generic title (e.g. `rig-1 · claude · %3 needs input`), an optional deep link, and an optional fetch reference. Every string field is secret-scanned at validation with no bypass path.

Body content (command output, pane text, diffs) is staged in the daemon's **tailnet-only HTTPS content store** and referenced by a fetch URL in the wake:

- The listener binds the resolved tailnet IP only (never `0.0.0.0`), default port **2587**, TLS from the Tailscale-issued `*.ts.net` certificate. If TLS material is unavailable the listener stays off — it never falls back to plaintext.
- Content tokens are single-use and TTL'd (`content_store.ttl_seconds`, default 600s, valid 30–3600). Bodies are capped at 64 KiB.
- Fetching requires the device's per-device bearer (`Authorization: Bearer`, constant-time verify). Any auth failure or token miss returns a uniform 404 — no oracle distinguishes a bad bearer from an expired token.

## The default path: UnifiedPush / self-hosted ntfy

`gateway.unifiedpush.enabled` defaults to **true** — this is the sovereign, default-on wake path. The daemon POSTs the opaque metadata JSON (`msg_id`, `host`, `session`, `deep_link`, `fetch_url`, `fetch_ttl_s`) directly to the device's UnifiedPush endpoint on your self-hosted ntfy server, with the generic title in a header. The endpoint URL is treated as secret-class and is never logged. When the ntfy admin password is present in the OS keychain, the request carries Basic auth; otherwise it degrades to unauthenticated (for tailnet-private servers).

No third party is involved: daemon → your ntfy server → your phone, all over the tailnet.

## Experimental legs: APNs and FCM

Both are **disabled by default** and experimental (`gateway.apns.enabled: false`, `gateway.fcm.enabled: false`). Current enrollment mints only UnifiedPush tokens — these legs ship interface-complete and wait on the v5 mobile receiver.

| Leg | Transport | Credentials | Notes |
|-----|-----------|-------------|-------|
| APNs | Direct to `api.push.apple.com` (no third-party relay), token-based `.p8` auth | `gateway.apns.key_source: keychain` (default) or `file` | `bundle_id` required when enabled. Alert-type push only, priority 10 — background push is structurally absent |
| FCM | Firebase Cloud Messaging HTTP v1 | `gateway.fcm.creds_source: keychain` (default) or `file` (GCP service-account JSON) | Sends the same opaque metadata as data fields |

When a provider reports a token permanently dead (APNs 410, FCM `UNREGISTERED`), the device is auto-revoked in the enrollment store and its queued wakes are dropped.

## Outbox, retries, receipts

Wakes are not fire-and-forget. The daemon fans each notification out to every active enrolled device through a persistent **bbolt outbox** (`push_outbox.db` — daemon runtime state, deliberately outside the audit trail):

- A retry goroutine scans every 5s and dispatches due entries; transient failures back off exponentially (5s base, 5m cap).
- Duplicate suppression: each `msg_id` is remembered for 24h after successful delivery.
- Per-device wake ceiling: 60 wakes/hour. `approval_request` wakes are exempt — a safety-critical approval is never rate-limited away.
- Seven gateway counters (`queued`, `sent`, `provider_accepted`, `pruned_tokens`, `ceiling_dropped`, `backoff_pending`, `fanout_errors`) are exposed on the daemon's `GET /status`.

Delivery receipts: the phone can `POST /ack` (bearer-gated) after it fetches a wake. The daemon appends a **hash-only** receipt to the audit chain — a SHA-256 over the msg ID and device ID, never the raw values — so `abysslink status` can report wake-sent vs ack-received honestly. A missed ack triggers nothing: there is no automatic re-wake, by design.

## One-scan enrollment

`abysslink enroll phone --apply` delivers per-device credentials (bearer, push token, SSH key + certificate) with a single QR scan:

1. The CLI stages the one-time credential bundle in the daemon's content store under a single-use **bootstrap token** (`ablk_e_…` prefix, TTL `content_store.enroll_ttl_seconds`, default 300s, valid 30–900).
2. It prints one QR encoding `https://<rig>.ts.net:2587/enroll/<token>`.
3. The phone (already on the tailnet at this step) scans and pulls the bundle. The pull is bearer-less — this is first contact, the token's 256-bit entropy is the credential — single-use, and any miss is a uniform 404 that burns nothing.

If the daemon is not running, enrollment degrades to printing the bundle in the terminal (optionally as per-credential QRs with `--qr`) and tells you how to enable the one-scan pull (`abysslink daemon enable --apply`).

## The session registry

`session_registry.enabled` defaults to **true**. The daemon watches your tmux server and turns "a pane went quiet at a prompt" into the `rig · session · pane needs input` notification:

- Panes are polled every 5s while active, backing off to 15s when everything is idle.
- A pane is `needs_input` when its content looks prompt-shaped and it has produced no output for `idle_secs` (default 30s, floor 10s).
- Re-notification for the same pane and kind is suppressed for `cooldown_secs` (default 300s).

```yaml
session_registry:
  enabled: true            # default
  ignore_sessions: []      # session names exempt from the heuristic
  idle_secs: 30            # 0 = 30; floor 10
  poll_active_secs: 5      # 0 = 5
  poll_idle_secs: 15       # 0 = 15
  prompt_regex: ""         # extends the built-in prompt sentinels; must compile
  cooldown_secs: 300       # 0 = 300
```

Session/window/pane names appear in wake metadata for routing — pick neutral tmux session names if that matters to you (see [Who sees what](who-sees-what.md)).

## Related pages

- [Who sees what](who-sees-what.md) — per-broker visibility table.
- [Agent safety](agent-safety.md) — how approve/deny buttons ride this same path.
- [Configuration reference](configuration.md) — `gateway`, `content_store`, and `session_registry` keys.
- [ntfy module](modules/ntfy.md) — the self-hosted ntfy server itself.
- [Push real-device runbook](testing/push-real-device.md) — verifying delivery end to end.
