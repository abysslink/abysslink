# Fleet Notify Verification — SC-5 HMAC Verifier Recipe

This document describes how a subscriber (e.g. the ntfy mobile app or a custom
webhook processor) can verify that a notification originates from a specific
Abysslink rig and has not been tampered with.

**Assumption A3:** There is no Go subscriber in this repository. The verifier is
the ntfy mobile app receiving the notification, using this recipe to validate
the rig-identity headers.

---

## Overview

When `abysslink notify --all-rigs` sends a notification to a rig's ntfy topic,
it attaches three HTTP headers:

| Header | Content |
|--------|---------|
| `X-Abysslink-Rig` | The rig's logical name (e.g. `laptop-alpha`) |
| `X-Abysslink-Rig-Ts` | Epoch-seconds timestamp as a decimal integer string |
| `X-Abysslink-Rig-Sig` | Lowercase hex HMAC-SHA256 signature |

The signature proves which rig sent the notification. Because the HMAC key is
stored only in the OS keychain (never on disk, in YAML, or on argv), an
attacker without keychain access cannot forge a valid signature.

---

## Canonical String

The signature is computed over the following canonical string:

```
rigName + "." + ts + "." + title + "." + message
```

Where:
- `rigName` is the value of `X-Abysslink-Rig`
- `ts` is the value of `X-Abysslink-Rig-Ts` (epoch seconds, decimal string)
- `title` is the value of the `X-Title` header (the notification subject shown on the phone)
- `message` is the HTTP request body (the notification body text)

The timestamp is transmitted alongside the signature so the verifier can
reconstruct the canonical string. Without the timestamp, the verifier cannot
recompute the HMAC (see Pitfall 6 in the security design).

**WR-02:** The title (`X-Title`) is explicitly included in the signed payload so
that a relay between the CLI and the ntfy server cannot silently alter the displayed
notification subject (e.g. "Build complete" → "All is well") without breaking the
HMAC. The title must be extracted from the `X-Title` header and included in the
canonical string in the order shown above.

---

## Signing Algorithm

The signature is `hex(HMAC-SHA256(key, canonical_string))` where:
- `key` is the 32-byte signing key decoded from its hex-encoded form
- `canonical_string` is `rigName + "." + ts + "." + title + "." + message`
- The hash function is SHA-256

---

## Verification Recipe

### Step 1: Retrieve the per-rig signing key

The per-rig HMAC signing key is stored in the OS keychain under:
- **Service:** `abysslink-rig-<rigName>` (e.g. `abysslink-rig-laptop-alpha`)
- **Account:** `hmac-signing-key`

On macOS:
```bash
security find-generic-password -s "abysslink-rig-laptop-alpha" -a "hmac-signing-key" -w
```

The key is a 64-character lowercase hex string (32 bytes encoded as hex).

### Step 2: Extract the headers and body

From the incoming ntfy notification:
```
rig_name = X-Abysslink-Rig header value
ts       = X-Abysslink-Rig-Ts header value
sig      = X-Abysslink-Rig-Sig header value
title    = X-Title header value   ← included in signature since Phase 14 (WR-02)
message  = notification body
```

### Step 3: Recompute the HMAC

Build the canonical string (note: title is now the third component, before message):
```
payload = rig_name + "." + ts + "." + title + "." + message
```

Compute HMAC-SHA256:
```python
import hmac, hashlib, binascii

key_hex = "..."  # 64-char hex key from keychain
title   = "..."  # X-Title header value
payload = rig_name + "." + ts + "." + title + "." + message

key_bytes = binascii.unhexlify(key_hex)
expected_sig = hmac.new(key_bytes, payload.encode("utf-8"), hashlib.sha256).hexdigest()
```

### Step 4: Compare using constant-time comparison

**CRITICAL:** Always use a constant-time comparison function. Never use `==`
on MAC values — byte-by-byte equality leaks timing information that enables
length-extension and forgery attacks.

In Python:
```python
import hmac

# hmac.compare_digest is the Python equivalent of Go's hmac.Equal
if hmac.compare_digest(expected_sig, received_sig):
    print("Signature valid — notification is authentic")
else:
    print("Signature INVALID — notification may be forged or tampered")
```

In Go (if implementing a custom webhook receiver):
```go
import (
    "crypto/hmac"
    "encoding/hex"
)

// ALWAYS use hmac.Equal — never byte ==
// This is a constant-time comparison that prevents timing attacks (T-14-02).
expectedBytes, _ := hex.DecodeString(expectedSig)
receivedBytes, _ := hex.DecodeString(receivedSig)
if hmac.Equal(expectedBytes, receivedBytes) {
    // Notification is authentic
}
```

In shell (using openssl):
```bash
KEY_HEX="..."   # 64-char hex from keychain
RIG_NAME="laptop-alpha"
TS="1717264200"
TITLE="Build done"   # X-Title header value (WR-02: included in signature)
MSG="CI passed"

PAYLOAD="${RIG_NAME}.${TS}.${TITLE}.${MSG}"
EXPECTED=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$(echo "$KEY_HEX" | xxd -r -p)" | awk '{print $2}')
echo "Expected: $EXPECTED"
echo "Received: $RECEIVED_SIG"
```

---

## Security Notes

1. **Never use `==` on signature bytes.** Always use a constant-time comparison
   (`hmac.Equal` in Go, `hmac.compare_digest` in Python). A byte-by-byte `==`
   leaks timing information that can enable signature forgery attacks.

2. **Verify the timestamp is recent.** Optionally reject notifications where
   `abs(now - ts) > threshold` (e.g. 5 minutes) to defend against replay attacks.

3. **The signing key must stay in the keychain.** It is never written to
   `abysslink.yaml`, the audit log, argv, or any log file. If you need to rotate
   the key, run `abysslink enroll rig <name> --apply` again.

4. **Per-rig isolation.** Each rig has its own unique signing key and its own
   ntfy topic. A notification signed by Rig A's key will never verify against
   Rig B's key. The per-rig topic ensures Rig A's events never appear in Rig B's
   topic feed.

5. **If `X-Abysslink-Rig-Sig` is absent,** the rig was not enrolled with a
   signing key (or was enrolled before Phase 14). The notification is unsigned
   and its origin cannot be cryptographically verified. Treat it as untrusted.

---

## Example: Verifying in Go

```go
package main

import (
    "crypto/hmac"
    "encoding/hex"
    "fmt"

    fleetpkg "github.com/abysslink/abysslink/internal/fleet"
)

// verifyNotification validates an incoming ntfy notification.
// title is the X-Title header value (included in signature since Phase 14, WR-02).
func verifyNotification(hexKey, rigName, ts, title, message, sigHex string) bool {
    // fleet.VerifyRigMessage uses hmac.Equal internally (constant-time).
    return fleetpkg.VerifyRigMessage(hexKey, rigName, ts, title, message, sigHex)
}

func main() {
    // Example values from an incoming ntfy notification:
    rigName := "laptop-alpha"
    ts      := "1717264200"
    title   := "Build done"                    // X-Title header (WR-02: now signed)
    message := "Build finished: CI passed"
    sigHex  := "<X-Abysslink-Rig-Sig header value>"
    hexKey  := "<per-rig key from keychain>"

    ok := verifyNotification(hexKey, rigName, ts, title, message, sigHex)
    fmt.Println("authentic:", ok)

    // Tamper test: modify the message — signature must fail.
    ok2 := verifyNotification(hexKey, rigName, ts, title, "tampered", sigHex)
    fmt.Println("body tampered:", ok2) // false

    // Tamper test (WR-02): modify the title — signature must also fail.
    ok3 := verifyNotification(hexKey, rigName, ts, "tampered subject", message, sigHex)
    fmt.Println("title tampered:", ok3) // false

    // Constant-time raw bytes comparison (equivalent):
    expected, _ := fleetpkg.SignRigMessage(hexKey, rigName, ts, title, message)
    expBytes, _ := hex.DecodeString(expected)
    rcvBytes, _ := hex.DecodeString(sigHex)
    fmt.Println("hmac.Equal:", hmac.Equal(expBytes, rcvBytes))
}
```

---

## References

- `internal/fleet/identity.go` — `SignRigMessage`, `VerifyRigMessage`
- `internal/cli/cmd_notify.go` — `sendNotifyAllRigs`, `sendRigNotify`
- Security control SC-5: "HMAC rig-identity headers on notify fan-out"
- Threat T-14-17: Spoofing via forged notification origin
- Threat T-14-18: Cross-topic delivery (Rig A event to Rig B topic)
- Threat T-14-19: HMAC key leakage via argv/audit
- Threat T-14-20: Tampered message (verifier can't recompute without timestamp)
- WR-02: Title (X-Title) now included in HMAC canonical string to prevent relay from
  silently altering the displayed notification subject without breaking the signature.

**Breaking change note:** If you have an existing verifier that used the Phase 14.0
canonical string `rigName + "." + ts + "." + message`, update it to use
`rigName + "." + ts + "." + title + "." + message` to match the new format.
