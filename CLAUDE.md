# CLAUDE.md — Instructions for Claude Code

You are implementing **Abysslink**, an open-source Go CLI that automates a secure phone-to-laptop remote-control setup over Tailscale. This file is the first thing you should read in this repo.

## Order of operations

1. **Read [docs/DESIGN.md](docs/DESIGN.md) end-to-end.** It's long. Don't skip sections. Sections 0, 2.0, 4, 6, 7 are load-bearing.
2. **Read [docs/IMPLEMENTATION-TASKS.md](docs/IMPLEMENTATION-TASKS.md) end-to-end.** Especially the "Conventions" section at the top.
3. **Skim [docs/BUSINESS.md](docs/BUSINESS.md).** You won't act on it, but knowing why monetization is deferred to v2+ helps you make consistent product calls.
4. **Then start Phase 0.** Each phase has explicit acceptance criteria — make them pass before declaring a phase done.

## Execution rules

### Stop after each phase

Phase 0, Phase 1, Phase 2, etc. — at the end of each, **stop and report back**. Include:

- What you built (file paths + one-line summary each).
- Which acceptance criteria pass, which don't, why.
- What you'd do next.
- Any decisions you made that weren't in the spec, with rationale.

Wait for explicit "continue to Phase N+1" before moving on. The user wants checkpoints.

### Decisions you must not relitigate

See `docs/IMPLEMENTATION-TASKS.md` — "Cross-cutting decisions Claude Code should not relitigate". Briefly:

1. **Go**, not Python. Single static binary.
2. **Apache-2.0** license. Not MIT, not GPL.
3. **No mobile app** in v1.
4. **Tailscale** is the default backend; self-hosted **Headscale** and **NetBird** control planes are also supported (shipped in v3.0.0 — the original v1 plan deferred them).
5. **ntfy** is the default notification backend.
6. **OS keychain** for secrets. Vaultwarden module deferred to v2+.
7. **`--dry-run`** is the default for destructive ops.
8. **Audit log + backup** on every file mutation. Non-negotiable.
9. **No telemetry** in v1. Period.
10. **YAML config** (`abysslink.yaml`), not TOML, not JSON.

If you find yourself wanting to deviate from these, stop and ask first.

### Hard rules

- **No `fmt.Println`** in library code. Use `log/slog` for logs. Only the `internal/cli` package may write to stdout/stderr, and only via the `Printer` abstraction so tests can capture.
- **Every external command call** goes through `internal/shell.Runner` — never call `os/exec` directly outside that package. This is so tests can mock cleanly.
- **Every file mutation** goes through `internal/audit` — never call `os.WriteFile` directly outside that package. Audit writes a backup + audit-log entry.
- **`--dry-run` is the default** for any command that mutates the system. Explicit `--apply` flag required.
- **No `sh -c`** shellouts — always `exec` the binary directly with argv.
- **No panics** in normal control flow. Return errors.
- **`context.Context` everywhere.** Cancellation must propagate.
- **License header** in every Go source file (Apache-2.0 short form).
- **No secrets on argv.** If a command takes a secret (API key, password), read from stdin or env, not from a flag.
- **No secrets in audit log.** Audit writes title + diff hash, never body content that might contain a token.

### Coding conventions

- Go 1.26+ (`go.mod` targets go 1.26.4). Module path: `github.com/abysslink/abysslink`.
- Lint with `golangci-lint` per `.golangci.yml` (errcheck, gosec, revive, gofmt, goimports, gocyclo, ineffassign, unused, staticcheck).
- Tests required for every non-trivial function. Use `testify` for assertions, `httptest.Server` for HTTP mocking, fixtures in `testdata/`.
- Run `make lint test` before declaring a phase complete.
- Commits: small, focused, conventional-commit format (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`). DCO sign-off (`git commit -s`).
- One PR per phase, even if you're working solo — the diff is the documentation.

### When you're uncertain

Defer to the spec docs. If the spec is ambiguous, ask the user — don't guess on a load-bearing decision. Use the original 7-file setup guide (the user's hand-written `remote setup/` markdown that this project is productizing) as the security source of truth. **Never weaken a default that the original guide sets.** Examples of immutable defaults:

- SSH `checkPeriod` is 12h, settable down but never up without an explicit `--accept-checkperiod-extension` flag.
- Tailnet Lock is on by default. Disablement secrets are printed once, never stored on disk.
- ntfy binds to the tailnet IP only, never 0.0.0.0.
- Tailscale Funnel is permanently rejected at the YAML schema level.
- FileVault (macOS) / LUKS (Linux) is required — `abysslink doctor` fails closed if disk is unencrypted.

### Positioning

The product has a deliberately twin identity:

- **Marketed as:** *Vibe-code Claude from your phone.* This goes in the README hero, the launch tweet, the demo video.
- **Built as:** A generic phone-to-rig toolkit. Claude Code is *one* opt-in consumer of the generic `notify` module, not a core dependency.

Implication for engineering: **the architecture stays generic.** Do not couple any core module to Claude. The `claudecode` module is one of many possible consumers. When marketing copy says "vibe-code Claude from your phone," the code underneath says nothing about Claude.

If you find Claude-specific logic creeping into the `notify`, `watch`, `tailscale`, `ssh`, `tmux`, or `mosh` modules, you're doing it wrong. That logic belongs in the `claudecode` module.

### Repo layout

Defined in `docs/DESIGN.md` §10. Build it exactly as specified — Claude Code's first commit is the empty skeleton with `doc.go` files in every package.

### Phase 0 starts now

Read the docs, build the skeleton, run `make lint test`, report back. Then we'll do Phase 1 together.

Good luck. Build something the user will be proud to type `abysslink up` for every morning.

---

## When the user asks something not covered here

- "Why X?" — answer from `docs/DESIGN.md` if covered there. If not, ask.
- "Can we change Y?" — if Y is in the "decisions you must not relitigate" list, push back and explain. If not, weigh the change and offer trade-offs.
- "Add feature Z" — check if it fits the v1 scope or belongs in a later phase. Don't accept scope creep silently.
- "Make it faster / smaller / better" — point at the performance budget in Task 8.3 and the security review in Task 8.2.

## Things to read once you're past Phase 1

- The user's original 7-file setup guide (in a sibling folder, `remote setup/`) — this is the security source of truth. Every footgun documented there must have a corresponding `abysslink doctor` check.
- The Tailscale CLI / SDK docs — `tailscale.com/tsnet`, `tailscale.com/client/local`, `github.com/tailscale/hujson`.
- The original `06-notifications.md` for the exact Claude Code hook semantics the `claudecode` module reproduces.

---

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->
