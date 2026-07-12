# Contributing to Abysslink

## Getting started

```bash
git clone https://github.com/abysslink/abysslink
cd abysslink
make dev-setup   # one-time: wires .githooks (pre-commit gitleaks secret scan)
make lint test
```

`make dev-setup` also enables the commit-msg hook that enforces DCO sign-off locally.

## Commit format

Use conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`

Example: `feat(ssh): enforce checkPeriod 12h default`

## DCO sign-off

Every commit **must** include a `Signed-off-by` line via `git commit -s`:

```
Signed-off-by: Your Name <your@email.com>
```

This is the Developer Certificate of Origin (DCO 1.1) — it is **not** a CLA.
By signing off you certify that you wrote or have the right to submit the contribution.
See https://developercertificate.org/ for the full text.

## Pull requests

- One PR per phase (or logical unit of work)
- Include `make lint test` output in the description
- All commits in the PR must have DCO sign-off
- Target the `main` branch

## License

All contributions are licensed under Apache-2.0.
By submitting a PR you agree your contribution is licensed under the same terms.
