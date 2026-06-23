# Who Sees What

The immutable rule from v4.0.0: the push payload carries routing metadata only — no body, no secrets, no code. Content is fetched over the tailnet after wakeup. This page documents exactly what each push broker receives, per path.

## Per push path

| Push path | What the broker sees | What the broker never sees |
|---|---|---|
| **UnifiedPush / self-hosted ntfy (sovereign)** | Device push token; generic title (e.g., `rig-1 · claude · %3 needs input`); opaque session ULIDs | Notification body; code content; secrets; tailnet IP; any content fetched from the daemon after wakeup |
| **FCM (experimental)** | FCM registration token; same generic title + opaque session IDs | Body content; tailnet address; per-device bearer credential; fetch URL |
| **ntfy.sh iOS relay (experimental)** | ntfy.sh topic hash; same generic title + opaque session IDs; relay timing metadata | Body content; tailnet address; per-device bearer credential; fetch URL |

> Both FCM and ntfy.sh relay paths are experimental. The sovereign UnifiedPush path via a self-hosted ntfy instance is the only production-ready push path in v4.0.0.

## Sovereignty ranking

1. **UnifiedPush / self-hosted ntfy** — no third party involved; the push travels from your daemon directly to your ntfy server, and from there to your phone. Data stays entirely on your tailnet and your own server.
2. **FCM** — Google receives the FCM registration token and the generic title. Body content is still fetched over the tailnet after wakeup; Google never sees it.
3. **ntfy.sh iOS relay** — ntfy.sh acts as an Apple APNs relay to reach iOS devices without a dedicated app. ntfy.sh sees the ntfy topic hash and the generic title. Body content is still fetched over the tailnet; ntfy.sh never sees it.

## Verifying the invariant

The push-payload enforcement lives in `internal/notifyv2/message.go` and `internal/push/gateway.go`. The `Message` type carries only routing fields (rig ID, session ULID, agent tag, pane ref) — there is no body field. The body is stored in the daemon's tailnet-only content store and fetched by the phone after wakeup using a single-use, TTL'd bearer token over the tailnet.

For full verification instructions, including how to inspect the payload your ntfy server receives, see [VERIFYING.md](VERIFYING.md).
