# Hardware-Backed SSH Keys & Boot-State Attestation

Phase 37 adds two opt-in security layers:

1. **Hardware-backed SSH keys** (`internal/hwkey`) — mint SSH keys whose
   private half lives inside the macOS Secure Enclave or a FIDO2
   authenticator, never on disk.
2. **Local boot-state attestation** (`internal/attest`) — `status` and
   `doctor` read your machine's boot-security posture (SIP, Secure Boot, TPM)
   and surface it honestly.

Both ship **disabled**. Enabling them never weakens any existing default.

---

## Why hardware keys

A key file on disk — even encrypted — can be exfiltrated and brute-forced
offline. An `sk`-type OpenSSH key can't: the file abysslink stores is a
**handle**; the private key is generated inside, and never leaves, the Secure
Enclave or the authenticator. Every signature requires the hardware, and every
connection requires **user presence** (a touch, and a PIN where
verify-required applies).

## The fail-closed contract

The entire feature is built around one rule: **abysslink never silently falls
back to a software key.**

- Enrollment succeeds only when the produced public key is *verifiably*
  sk-backed (its type token is `sk-ssh-ed25519@openssh.com` /
  `sk-ecdsa-sha2-nistp256@openssh.com` **and** `ssh-keygen -l` reports an
  `-SK` type). Anything else: the produced files are **deleted** and the
  command fails.
- A key type typo in config (`ed25519` instead of `ed25519-sk`) is refused at
  config load *and* again by the provider before any command runs.
- A missing tool, an OpenSSH older than 10.0, a mixed Apple/Homebrew
  toolchain, or a missing sk-api middleware is a refusal — never a "probably
  fine" path.
- `abysslink status` reports `key_kind: hardware:<provider>` **only after**
  re-verifying the on-disk public key is sk-backed. An unverifiable key is
  `unknown`, never hardware.
- The `sec-hwkey-kind` doctor check is **FATAL in every profile** if hardware
  keys are enabled but the active key is verifiably a software key — the
  silent-downgrade case is the one this feature exists to catch.

## Enabling

```yaml
hardware_keys:
  enabled: true
  provider: fido2            # or: secure-enclave (macOS)
  key_type: ed25519-sk       # fido2 only; enclave is always ecdsa-sk (P-256)
  # fido2_provider_path: /opt/homebrew/lib/libsk-libfido2.dylib   # macOS + external token
  # resident: true           # discoverable credential (stored on the token)
```

Or pick it during rig enrollment:

```console
$ abysslink enroll rig workstation --key-kind fido2 --apply
```

`enroll rig` only *writes the config stanza* — it never runs the interactive
keygen. The key itself is minted by a separate, deliberately interactive
command:

```console
$ abysslink enroll hardware-key            # dry-run: probe + exact commands
$ abysslink enroll hardware-key --apply    # interactive: touch / PIN on YOUR terminal
```

`--apply` requires a live terminal and rejects `--json`: authenticator PINs
and passphrases are entered directly on your terminal and read by OpenSSH
itself — abysslink never reads, stores, or transmits them.

## macOS Secure Enclave (`provider: secure-enclave`)

- Requires macOS with Apple's OpenSSH sk-api module
  (`/usr/lib/ssh-keychain.dylib`) and OpenSSH ≥ 10.0 (`ssh` and `ssh-keygen`
  from the *same* installation).
- The identity is created with `sc_auth create-ctk-identity -k p-256-ne -t
  bio`: **non-exportable** P-256, protected by biometrics. `p-256-ne` is the
  only key type abysslink will ever place on a `sc_auth` argv; the exportable
  `p-256` is unreachable by construction.
- `ssh-keygen -K` then downloads the **handle** into a fresh directory; the
  private key never leaves the enclave.
- `-K` downloads a handle for *every* resident key, not just the new one. If
  your Mac already has other enclave SSH identities, abysslink selects the
  handle carrying the just-created label — and **refuses** (installing
  nothing) when it cannot uniquely identify it. It never guesses which
  credential it just minted.
- Enclave keys are always `sk-ecdsa-sha2-nistp256@openssh.com` (the SK
  interface is P-256 only; `ed25519-sk` on the enclave is rejected at config
  load).

## FIDO2 authenticators (`provider: fido2`)

- `ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:abysslink`.
  `-O verify-required` is always set; **`-O no-touch-required` is not
  expressible** — there is no config field and no code branch that can emit
  it.
- On Linux the distro OpenSSH's internal USB HID support is used directly.
- On macOS, stock Apple `ssh-keygen` has **no USB middleware** — set
  `hardware_keys.fido2_provider_path` to an sk-api library (Homebrew OpenSSH's
  `libsk-libfido2.dylib` or your own build). Without it the provider reports
  unavailable; it never retries without `-w`.
- `key_type: ecdsa-sk` is an explicit opt-down for old U2F-only firmware.

## Connecting

Every connection needs explicit options — they prevent ssh from silently
succeeding with some *other* credential:

```console
ssh -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o SecurityKeyProvider=/usr/lib/ssh-keychain.dylib \
    -i ~/.ssh/abysslink_id_sk <user>@<host>
```

(Drop `SecurityKeyProvider` on Linux FIDO2; use your configured dylib for
macOS external tokens. Always pass it as a flag — some builds ignore the
`SSH_SK_PROVIDER` environment variable.)

## Boot-state attestation

`abysslink status` shows an **Attestation** row and `--json` an `attestation`
field: `verified` | `unverified` | `weakened`. `abysslink doctor` runs the
underlying probes as `sec-attest-*` checks:

| Check | Platform | Probe |
|---|---|---|
| `sec-attest-sip` | macOS | `csrutil status` |
| `sec-attest-secureboot` | macOS | `csrutil authenticated-root status` + iBridge boot-policy JSON |
| `sec-attest-secureboot` | Linux | `SecureBoot`/`SetupMode` EFI variables (+ `mokutil` corroboration, downgrade-only) |
| `sec-attest-tpm` | Linux | `tpm2_pcrread` (TCTI pinned to `/dev/tpmrm0`) |

The tri-state is **fail-closed**: only an exact-match affirmative literal
yields OK. A missing tool, a permission error, or unrecognized output is WARN
— never a false OK — and a *verified* weakened posture (SIP disabled, Secure
Boot byte 0) is distinguished from "cannot verify" in the message. Exit codes
are never trusted (`csrutil` and `mokutil` exit 0 even when the feature is
disabled).

By default the attestation checks report WARN so a pre-existing install that
was green yesterday stays usable; `doctor --profile at-risk` tightens every
attestation WARN — and the hardware-key WARN cases — to FATAL.

`internal/attest` is **local-only by construction**: an import-allowlist test
(`TestAttestNoNetworkImports`) fails the build gate if the package ever gains
a network-capable import. No SaaS verifier, no phone-home.

## Honest limitations

- **Local posture ≠ remote attestation.** abysslink reads local boot state
  (SIP, Secure Boot variables, TPM PCR *presence*). It does not produce
  signed TPM quotes and cannot prove runtime integrity to a remote party.
- **Enclave vs. external FIDO2 keys are type-indistinguishable.** Both
  surface as `sk-ecdsa-sha2-nistp256@openssh.com`; provenance comes from your
  own config plus the audit trail, and `status` reports the *configured*
  provider kind only after verifying sk-backing.
- **Agent-served enclave keys (e.g. Secretive) are classified software.**
  They present as plain `ecdsa-sha2-nistp256` public keys, which is
  cryptographically indistinguishable from a disk-backed key — abysslink
  refuses to overclaim and reports them as software.
- **Intel T2 Macs** fall into the WARN taxonomy for Secure Boot (the T2
  `nvram` probe is not shipped in v1) — indeterminate, never falsely green.
