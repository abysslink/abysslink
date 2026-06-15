# Push Gateway Real-Device Test Runbook (SC#1 / D-20)

This runbook documents the manual real-device test procedure for the Phase 29
opaque-wake → tailnet-fetch → ack loop. It corresponds to the automated scaffold
in `internal/push/integration_test.go`.

---

## Purpose

The integration test (SC#1, D-20) validates the full end-to-end wake path on real
de-Googled Android hardware with the screen **off** and Doze **active**. This
cannot be automated in CI because it requires a physical phone, a running tailnet,
and a human observer to confirm screen wake and notification rendering.

---

## Prerequisites

Before running the test, ensure all of the following are true:

- **De-Googled Android device** with [ntfy](https://ntfy.sh) app installed and
  UnifiedPush enabled (ntfy → Settings → Enable UnifiedPush).
- **Device enrolled in abysslink**: `abysslink enroll phone --apply` completed
  successfully and the device appears in `abysslink device list`.
- **abysslinkd running on the rig**: `abysslink daemon enable --apply` (confirm
  with `abysslink status` — daemon counter fields must be present).
- **Tailnet connection established**: rig and phone are on the same tailnet
  (`tailscale status` shows both as active peers).
- **Phone screen off** before running the test (locks the device after enrolling).
- **Content store healthy**: `abysslink doctor` must report no FATAL in the
  `push-gateway` or `content-store` groups.
- **ntfy endpoint URL available**: retrieve the enrolled device's endpoint from
  `abysslink device list` (the `push_token` / ntfy endpoint field).

---

## Environment Setup

```bash
# Required: the ntfy endpoint URL the phone is subscribed to.
# Obtain from: abysslink device list --json | jq -r '.[] | select(.name=="phone") | .push_token'
export PUSH_TEST_NTFY_ENDPOINT="https://ntfy.example.com/your-topic"

# Required: the enrolled device ULID.
# Obtain from: abysslink device list --json | jq -r '.[] | select(.name=="phone") | .id'
export PUSH_TEST_DEVICE_ID="01J2A8X3Q0B1ABCDEFGH"

# Optional: override daemon socket path (defaults to daemon.SocketPath() — XDG_RUNTIME_DIR or /tmp/abysslink).
# export PUSH_TEST_DAEMON_SOCKET="/run/user/1000/abysslink/abysslinkd.sock"
```

> **Security note:** `PUSH_TEST_NTFY_ENDPOINT` is a secret-class value (D-17).
> Do **not** echo it to logs, commit it to git, or include it in CI environment variables.
> Use a secrets manager or pass it interactively for ad-hoc runs.

---

## Test Invocation

```bash
go test -tags integration ./internal/push/... \
  -run TestRealDevicePush \
  -v \
  -timeout 120s
```

The `-tags integration` flag is required; without it the file is excluded from the
default `make test` run and does not compile.

---

## Expected Outcome

### Automated portion (asserted by the test)

| Counter | Expected |
|---------|----------|
| `gateway_queued` | Increments by ≥ 1 within 30 seconds of POST /notify |
| `gateway_sent`   | Increments by ≥ 1 (may take one retry loop cycle, ~5 s) |

### Manual portion (human observer required)

1. **Phone screen wakes** within 60 seconds of the push dispatch (Doze FCM/UnifiedPush
   high-priority wake signal).
2. **Notification visible** on the lock screen showing a safe generic title
   (no content body — opaque-wake invariant).
3. **Tapping the notification** opens the deep link and the phone fetches the
   actual content from the tailnet content store over HTTPS (`https://<rig-ts.net>:2587/content/<token>`).
4. **`abysslink status`** shows `ack_received` incremented after the phone fetches content.

---

## Doze Test Procedure

To confirm the wake path works under Android's battery-optimization Doze mode:

1. Connect the test phone via USB (ADB access required).
2. **Force the device into Doze** before running the test:
   ```bash
   adb shell dumpsys deviceidle force-idle
   ```
3. Lock the phone (screen off) and wait 5 seconds.
4. Run the integration test:
   ```bash
   go test -tags integration ./internal/push/... -run TestRealDevicePush -v -timeout 120s
   ```
5. **Observe the phone** — it must wake within **60 seconds** of the push dispatch.
   - If using UnifiedPush/ntfy: ntfy uses Firebase or UnifiedPush high-priority
     wake signal which is exempt from Doze (maintenance window not required).
   - If using APNs (experimental): high-priority alert push is Doze-exempt.
6. Exit Doze after the test:
   ```bash
   adb shell dumpsys deviceidle unforce
   ```

---

## Failure Modes and Diagnostics

| Symptom | Likely cause | Diagnostic |
|---------|-------------|------------|
| `GET /status` fails | abysslinkd not running | `abysslink daemon enable --apply` |
| `gateway_queued` does not increment | Outbox not wired | check `wirePushOutbox` in main.go logs |
| `gateway_sent` stays 0 | No UnifiedPush gateway registered | check wirePushOutbox logs; UnifiedPushGateway must be in gateways map |
| Phone does not wake | ntfy app not subscribed to endpoint | verify ntfy → subscriptions; re-enroll |
| Phone wakes but no content | Content store not healthy | `abysslink doctor` → push-gateway group |
| Doze: phone wakes after >60s | ntfy not using high-priority wake | update ntfy app; check server `X-Priority: urgent` header |

---

## Phase Summary Recording

After running this runbook, record the outcome in
`.planning/phases/29-push-gateway-outbox/29-05-SUMMARY.md` under a
**Real-Device Test Results** section:

```markdown
## Real-Device Test Results (SC#1 / D-20)

- **Date:** YYYY-MM-DD
- **Device model:** <e.g. Google Pixel 7a running GrapheneOS>
- **Android version:** <e.g. Android 14 / GrapheneOS 2024.xx.xx>
- **ntfy version:** <e.g. ntfy 2.11.0 (F-Droid build)>
- **Doze behavior:** <e.g. Phone woke within 12 seconds under forced Doze>
- **gateway_queued increment:** <yes/no + delta>
- **gateway_sent increment:** <yes/no + delta>
- **ack_received increment:** <yes/no + delta>
- **Outcome:** PASS / FAIL / PARTIAL
- **Notes:** <any deviations or observations>
```

This runbook must be re-executed before Phase 33 (Distribution & Public Launch)
to confirm the full wake path works on real hardware prior to the Show HN launch
gate (LNCH-05).
