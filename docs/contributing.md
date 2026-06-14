# Contributing

Thank you for your interest in contributing to Abysslink.

## Before you start

- Read [docs/DESIGN.md](https://github.com/abysslink/abysslink/blob/main/docs/DESIGN.md) — the full design document and the non-negotiable architectural decisions.
- Check existing [issues](https://github.com/abysslink/abysslink/issues) and [pull requests](https://github.com/abysslink/abysslink/pulls).

## Development setup

```sh
git clone https://github.com/abysslink/abysslink.git
cd abysslink
go mod download
make build
make test
make lint
```

Requirements:
- Go 1.26+ (`go.mod` targets go 1.26.4)
- `golangci-lint` v2 (install via `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`)
- `shellcheck` (for `scripts/install.sh` changes)

## Coding conventions

### Hard rules

- No `fmt.Println` in library code — use `log/slog`
- Every external command call goes through `internal/shell.Runner`
- Every file mutation goes through `internal/audit`
- `--dry-run` is the default for any command that mutates the system
- No `sh -c` shellouts — always `exec` the binary directly with argv
- No panics in normal control flow — return errors
- `context.Context` everywhere — cancellation must propagate
- License header (Apache-2.0 short form) in every Go source file
- No secrets on argv
- No secrets in the audit log

### Style

- `gofmt` and `goimports` — enforced by lint
- Conventional commit messages: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`
- DCO sign-off required: `git commit -s`
- Tests required for every non-trivial function

## Submitting changes

1. Fork the repository
2. Create a branch: `git checkout -b feat/my-feature`
3. Make your changes, ensuring `make lint test` passes
4. Commit with DCO sign-off: `git commit -s -m "feat: add my feature"`
5. Push and open a pull request

## Pull request checklist

- [ ] `make lint test` passes locally
- [ ] Tests added for new functionality
- [ ] Docs updated if user-facing behaviour changed
- [ ] Commit messages follow conventional commit format
- [ ] DCO sign-off on all commits (`git commit -s`)
- [ ] No secrets or credentials in the diff

## Security issues

Do not open a public issue for security vulnerabilities. Follow the process in [SECURITY.md](https://github.com/abysslink/abysslink/blob/main/SECURITY.md).

## Code of Conduct

See [CODE_OF_CONDUCT.md](https://github.com/abysslink/abysslink/blob/main/CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 license and that you have the right to make the contribution.
