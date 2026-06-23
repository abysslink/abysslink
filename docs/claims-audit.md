# Claims Audit

Every verifiable security claim in README and documentation maps to a code pointer in the root [CLAIMS-AUDIT.md](https://github.com/abysslink/abysslink/blob/main/CLAIMS-AUDIT.md) manifest. Run `bash scripts/claims-check.sh` to verify all pointers resolve on disk.

## How to read the manifest

Each row in `CLAIMS-AUDIT.md` has five columns:

- **#** — a stable `C-NN` identifier for the claim.
- **Claim (exact quote)** — the security sentence as it appears in README or docs, quoted exactly.
- **Source** — which file and section the claim appears in.
- **Code Pointer** — either a relative file path (e.g. `internal/audit/audit.go`) or a `doctor:check-id` reference (e.g. `doctor:disk-encryption`). File-path pointers may include a `:` suffix for a line number or function name, but the checker validates only the file portion. Compound pointers joined by ` + ` indicate that more than one code location enforces the claim.
- **Status** — `✓` when the pointer resolves; updated manually after each review.

Doctor-check IDs (`doctor:*`) reference runtime checks that `abysslink doctor` performs. They are not static files and are accepted by the checker without a disk lookup — they represent live enforcement rather than source locations.

## Enforcement

The checker (`scripts/claims-check.sh`) is **non-blocking**: it always exits 0 and prints warnings to stderr when a pointer is missing or does not resolve to a file on disk. This is an intentional locked decision (D-01): the checker warns during development and code review without blocking the release pipeline.

The final enforcement gate is the LNCH-04 manual operator sign-off: a human reviews `CLAIMS-AUDIT.md`, runs `bash scripts/claims-check.sh`, confirms zero warnings, and marks the gate passed before the launch runbook proceeds.

## Adding new claims

When you introduce a new security sentence in README or docs:

1. Add a new row to `CLAIMS-AUDIT.md` with a `C-NN` ID, the exact quoted claim, the source file and section, and the code pointer.
2. Run `bash scripts/claims-check.sh` and confirm it prints `claims-check: done (exit 0, non-blocking)` with zero warnings.
3. If the claim references a doctor check that does not yet exist, open a follow-up issue and mark the pointer as `doctor:pending-check-id` until the check is implemented.

The root manifest is the source of truth: [CLAIMS-AUDIT.md](https://github.com/abysslink/abysslink/blob/main/CLAIMS-AUDIT.md).
