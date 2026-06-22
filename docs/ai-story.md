# Built with AI

Abysslink was built in collaboration with AI coding assistants, primarily Claude Code. This page describes what that means, what was verified manually, and where the project takes personal responsibility for correctness.

## What AI helped with

- Code scaffolding and boilerplate for Go packages and CLI structure.
- Test generation — unit tests, table-driven tests, fuzz corpus seeds.
- Documentation drafts — prose sections of README, quickstart, and module docs.
- Security threat enumeration — brainstorming and classifying threats for the threat model.

## What we verified manually

- Every security decision: Tailscale Funnel rejection at the schema level, ntfy bind floor (tailnet-IP only, never `0.0.0.0`), audit log schema (title and diff hash only, never body content), and all other immutable defaults.
- The full threat model, including which threats are accepted vs. mitigated and why.
- Every `abysslink doctor` check — each one was reviewed to confirm it fails closed on the condition it guards against.
- The supply-chain pipeline — SLSA L3 provenance via `actions/attest-build-provenance`, cosign signing, Grype + VEX suppression, and the `repro-check` workflow for reproducible builds.
- Real-device testing of the push-notification path: sovereign UnifiedPush via self-hosted ntfy, the opaque-payload fetch flow, and the phone approve loop.

## Responsibility

We review every AI-generated change before merging. Security-critical code paths carry manual audit trails in [CLAIMS-AUDIT.md](https://github.com/abysslink/abysslink/blob/main/CLAIMS-AUDIT.md) — each claim maps to a specific source file that was read and understood by a human, not accepted on AI assurance alone.

## Limitations

AI assistance can produce plausible-looking but incorrect security logic. Common failure modes include: off-by-one errors in time-window enforcement, missing context-cancellation propagation, and overly broad error handling that swallows security-relevant failures. Every such pattern in Abysslink is in the claims register with a human-verified pointer. If you find a case where an AI-generated claim does not match the actual code behavior, please open an issue — that is exactly the kind of gap the [claims audit](claims-audit.md) process exists to catch.
