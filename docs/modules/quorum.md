# quorum — the quorum-sensing action gate

> Strictly speaking `quorum` is not a module (it has no Detect/Plan/Apply lifecycle and nothing to `enable`/`disable`): it is **gate policy**, a peer of the approve loop and the budget watcher, wired into the exec gate inside `abysslinkd`. This page exists as the module-style entry point; the full design lives in [Agent Safety → The quorum action gate](../agent-safety.md#the-quorum-action-gate).

## What it does

When the exec gate is enforcing (`gate.enforcing: true`), the quorum decides per action:

| Outcome | Meaning |
|---|---|
| **ALLOW** | Unanimous confident ALLOW from all four verifiers, no rule matched — the exec proceeds, audit-only. |
| **ESCALATE** | Anything less than unanimous confident ALLOW — the exec is routed to the existing phone/TTY approve loop at the demanded tier. |
| **DENY** | A stage-0 deny-floor hit, a canary tripwire, or a single-verifier veto — refused outright; a valid approval token does not bypass it. |

Four deterministic verifiers vote, each over a distinct input signal: V1 syntactic (raw argv), V2 policy (parsed intent + protected paths/branches), V3 behavior (temporal history), V4 reversibility (filesystem/VCS world state). Verifier failure of any kind escalates — never allows. No LLM, no network call.

With the gate in shadow mode (the default), the quorum still evaluates every exec asynchronously and audits the full vote vector — a day-one calibration corpus that never blocks anything.

## Configuration

The [`quorum:` stanza](../configuration.md#quorum) is tighten-only: add-only lists, lower-only spend threshold, raise-only tier overrides. Loosening below the shipped defaults is a config load error, and no key exists to remove or disable the compiled deny-floor.

## Tooling

- `abysslink quorum eval -- <cmd> [args…]` — read-only shadow evaluation printing the dissent-first vote vector; never executes.
- `abysslink doctor` — `sec-quorum-enabled`, `sec-quorum-floor`, `sec-quorum-selftest`, `sec-quorum-tripwire` verify the gate is armed, the floor is intact, the verifiers fail closed, and the tripwires fire. `--profile at-risk` escalates `sec-quorum-enabled` to FATAL.
