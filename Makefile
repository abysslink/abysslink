# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors

BINARY     := abysslink
DAEMON     := abysslinkd
MODULE     := github.com/abysslink/abysslink
GO         ?= go
GOLANGCI   ?= golangci-lint
GORELEASER ?= goreleaser

# GOSEC_EXCLUDES is the SINGLE source of truth for the standalone-gosec rule
# excludes (WR-06). Both `make lint` and the CI security gate
# (.github/workflows/security.yml) reference this via `make security-gosec`, so
# the two cannot drift. Each family is a project-wide verified false-positive /
# accepted risk documented with an inline #nosec/#nolint justification (SEC-02):
# G304 file-path-from-variable (internal trusted paths), G101 env-var/keychain
# name FPs, G302/G306 executable-binary 0o755, G204 shell.Runner sanctioned exec
# abstraction (CLAUDE.md), G703 taint-based path-traversal (the gosec >= 2.22
# successor to G304, same internal-trusted-path rationale). Genuine G115/G402
# and the verified-FP G118/G117/G122/G602 carry inline #nosec annotations.
GOSEC_EXCLUDES := G304,G101,G302,G306,G204,G703

# Build info
# COMMIT uses the FULL SHA to match goreleaser's {{.Commit}} injection, so a
# `make build` and the released binary agree on the embedded commit ldflag.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS    := -s -w \
  -X $(MODULE)/internal/cli.version=$(VERSION) \
  -X $(MODULE)/internal/cli.commit=$(COMMIT) \
  -X $(MODULE)/internal/cli.buildDate=$(BUILD_DATE)

.PHONY: build test lint cover release install clean conformance security-audit repro-check
.PHONY: check-webui-isolation check-webui-build-tags check-htmx-sri vendor-htmx security-gosec
.PHONY: vex-suppression-proof

## build: compile CLI and daemon binaries (reproducible: SOURCE_DATE_EPOCH from git)
build:
	SOURCE_DATE_EPOCH=$$(git log -1 --format='%ct') \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/abysslink
	SOURCE_DATE_EPOCH=$$(git log -1 --format='%ct') \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DAEMON) ./cmd/abysslinkd

## test: run all tests
test:
	$(GO) test -race -count=1 ./...

## lint: run golangci-lint (incl. gosec + nolintlint), gofmt, the webui build-tag
## gates, then the standalone gosec (via security-gosec) + semgrep scanners
## (SEC-02). Requires: gosec (go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1),
## semgrep (pipx install semgrep). The gosec excludes (GOSEC_EXCLUDES) mirror the
## golangci-lint gosec config + justified #nosec///nolint suppressions; the
## remaining real findings are fixed at the root or carry inline justifications.
lint: check-webui-build-tags check-webui-isolation
	$(GOLANGCI) run ./...
	@gofmt -l . | grep -v vendor | grep . && echo "gofmt: files need formatting (run gofmt -w .)" && exit 1 || true
	$(MAKE) security-gosec
	semgrep --config p/r2c-security-audit --config p/golang --error --quiet .

## security-gosec: run the standalone gosec scanner with the canonical exclude
## set (WR-06). This is the single command both `make lint` and CI invoke so the
## exclude list lives in exactly one place (GOSEC_EXCLUDES).
security-gosec:
	gosec -quiet -exclude=$(GOSEC_EXCLUDES) ./...

## check-webui-build-tags: assert every .go file under internal/modules/webui/
## carries //go:build webui (Pitfall 5 — a single untagged file leaks the package
## into the base build). WEB-01.
check-webui-build-tags:
	@missing=$$(grep -rL '//go:build webui' internal/modules/webui/*.go 2>/dev/null); \
	  if [ -n "$$missing" ]; then \
	    printf 'FAIL: files missing //go:build webui:\n%s\n' "$$missing"; exit 1; \
	  fi
	@echo "OK: all webui .go files carry the build tag"

## check-webui-isolation: build abysslinkd WITHOUT -tags webui and assert the
## base binary links zero web-DASHBOARD packages — the web UI server stack
## (internal/modules/webui) and its Tailscale safeweb HTTP framework
## (tailscale.com/safeweb). Uses `go list -deps` (authoritative, no false
## positives) as the primary gate and a precise `go tool nm` symbol scan as a
## belt-and-suspenders check. The patterns are the exact package import paths —
## NOT the bare string "webui", which would falsely match the base-package
## config.WebUIConfig type. WEB-01 / T-19-02.
##
## NOTE (phase 28.1): tailscale.com/client/local is deliberately NOT forbidden
## here. It was originally listed as a proxy for "webui present" (phase 19, when
## only the dashboard linked it), but the phase-28 tailnet content store
## (BACK-06) now legitimately links it in the BASE daemon for the content
## listener's WEB-03 TLS GetCertificate — a Tailscale-only cert path with no
## non-SDK alternative. It is a thin local-API client over the tailscaled
## socket, not the heavy safeweb dashboard stack this invariant exists to keep
## optional. Re-adding it would force-couple a core, non-optional feature to the
## opt-in build tag. The dashboard stack itself remains strictly tag-gated.
check-webui-isolation:
	@$(GO) build -o /tmp/abysslinkd-base ./cmd/abysslinkd
	@deps=$$($(GO) list -deps ./cmd/abysslinkd | grep -c 'internal/modules/webui\|tailscale.com/safeweb' || true); \
	  if [ "$$deps" -ne 0 ]; then \
	    echo "FAIL: base binary depends on $$deps web-dashboard package(s)"; \
	    $(GO) list -deps ./cmd/abysslinkd | grep 'internal/modules/webui\|tailscale.com/safeweb'; \
	    rm -f /tmp/abysslinkd-base; exit 1; \
	  fi
	@syms=$$($(GO) tool nm /tmp/abysslinkd-base | grep -c 'internal/modules/webui\|tailscale.com/safeweb' || true); \
	  if [ "$$syms" -ne 0 ]; then \
	    echo "FAIL: base binary contains $$syms web-dashboard symbol(s)"; \
	    rm -f /tmp/abysslinkd-base; exit 1; \
	  fi
	@rm -f /tmp/abysslinkd-base
	@echo "OK: base binary contains zero web-dashboard symbols"

## check-htmx-sri: verify the SHA-384 of the vendored htmx.min.js matches the
## HTMXIntegrity constant in sri_const_gen.go. Until Plan 03 vendors the real
## file, this exits 0 with a NOTICE when the asset is absent. WEB-06.
check-htmx-sri:
	@if [ ! -f internal/modules/webui/assets/htmx.min.js ]; then \
	  echo "NOTICE: htmx.min.js not yet vendored — run 'make vendor-htmx' first"; \
	else \
	  actual=$$(openssl dgst -sha384 -binary internal/modules/webui/assets/htmx.min.js | openssl base64 -A); \
	  expected=$$(grep 'const HTMXIntegrity' internal/modules/webui/sri_const_gen.go | cut -d'"' -f2 | sed 's/^sha384-//'); \
	  if [ "$$actual" != "$$expected" ]; then \
	    echo "FAIL: htmx SRI mismatch — re-run go generate ./internal/modules/webui/..."; exit 1; \
	  fi; \
	  echo "OK: htmx SHA-384 SRI matches sri_const_gen.go"; \
	fi

## vendor-htmx: download htmx 2.0.10 from the official GitHub release into the
## embedded assets dir (one-time setup; the executor runs this in Plan 03). Run
## `make check-htmx-sri` afterwards to verify integrity.
vendor-htmx:
	@mkdir -p internal/modules/webui/assets
	@curl -fsSL \
	  https://unpkg.com/htmx.org@2.0.10/dist/htmx.min.js \
	  -o internal/modules/webui/assets/htmx.min.js
	@echo "Downloaded htmx 2.0.10 — run 'make check-htmx-sri' to verify SRI"

## cover: run tests with coverage report
cover:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## release: build release artifacts via goreleaser (snapshot)
release:
	$(GORELEASER) release --snapshot --clean

## install: install CLI and daemon binaries to GOPATH/bin or GOBIN
install:
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/abysslink ./cmd/abysslinkd

## repro-check: build binary twice and assert byte-identical output
repro-check:
	@echo "=== Reproducibility check ==="
	@mkdir -p /tmp/abysslink-repro-1 /tmp/abysslink-repro-2
	SOURCE_DATE_EPOCH=$$(git log -1 --format='%ct') \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o /tmp/abysslink-repro-1/abysslink ./cmd/abysslink
	SOURCE_DATE_EPOCH=$$(git log -1 --format='%ct') \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o /tmp/abysslink-repro-2/abysslink ./cmd/abysslink
	@sha256sum /tmp/abysslink-repro-1/abysslink /tmp/abysslink-repro-2/abysslink
	@diff /tmp/abysslink-repro-1/abysslink /tmp/abysslink-repro-2/abysslink \
	  && echo "OK: byte-identical" \
	  || (echo "FAIL: binaries differ"; exit 1)
	@rm -rf /tmp/abysslink-repro-1 /tmp/abysslink-repro-2

## clean: remove build artifacts
clean:
	rm -f $(BINARY) $(DAEMON) coverage.out coverage.html
	rm -rf dist/

## conformance: build and run the end-to-end conformance test suite
## Uses ABYSSLINK_BIN so the suite tests the binary just built, not PATH.
conformance: build
	ABYSSLINK_BIN=./$(BINARY) $(GO) run ./cmd/abysslink-conformance

## security-audit: run the conformance suite (which covers binary size, secrets,
## telemetry, ntfy bind-addr, sshd directives, and all CLI gate checks) plus a
## final telemetry grep for belt-and-suspenders coverage.
security-audit: build
	@echo "=== Security Audit (conformance suite) ==="
	ABYSSLINK_BIN=./$(BINARY) $(GO) run ./cmd/abysslink-conformance
	@echo ""
	@echo "=== Belt-and-suspenders telemetry grep ==="
	@! grep -r \
		-e '"github.com/DataDog' \
		-e '"github.com/getsentry' \
		-e '"go.opentelemetry.io' \
		-e '"github.com/newrelic' \
		-e '"github.com/honeycombio' \
		-e '"github.com/segmentio/analytics' \
		-e '"github.com/posthog' \
		--include="*.go" \
		--exclude-dir=conformance \
		. \
		&& echo "OK: no telemetry imports found" \
		|| (echo "FAIL: telemetry imports found (see above)"; exit 1)
	@echo "=== Security audit complete ==="

## vex-suppression-proof: prove a VEX suppression actually fires (SUPL-03, Pitfall 3)
# Runs Grype over the fixture SBOM twice: WITHOUT --vex the known advisory
# (CVE-2020-26160 in the fixture's jwt-go package) must appear and grype must
# FAIL; WITH --vex the PURL-matching not_affected statement must suppress it and
# grype must PASS. If the WITHOUT run ever passes or the WITH run ever fails, the
# PURL match is wrong (silent-suppression bug) and CI must not be trusted.
# Requires `grype` on PATH (CI installs it pinned; install locally to run this).
# This is the executable form of 32-VALIDATION.md's SUPL-03 Manual-Only entry.
vex-suppression-proof:
	@command -v grype >/dev/null 2>&1 || { echo "grype not on PATH — install grype to run the suppression proof"; exit 2; }
	@echo "=== VEX suppression proof (SUPL-03) ==="
	@echo "--- 1/2: WITHOUT --vex (advisory MUST appear; grype MUST fail) ---"
	@if grype "sbom:security/vex/testdata/known-advisory.spdx.json" --fail-on high; then \
		echo "FAIL: grype passed WITHOUT --vex — fixture advisory not detected; the proof is meaningless"; exit 1; \
	else \
		echo "OK: grype failed WITHOUT --vex (advisory detected as expected)"; \
	fi
	@echo "--- 2/2: WITH --vex (advisory MUST be suppressed; grype MUST pass) ---"
	@if grype "sbom:security/vex/testdata/known-advisory.spdx.json" \
		--vex security/vex/testdata/known-advisory.openvex.json --fail-on high; then \
		echo "OK: grype passed WITH --vex (suppression fired — PURL match correct)"; \
	else \
		echo "FAIL: grype failed WITH --vex — suppression did NOT fire. PURL mismatch (Pitfall 3): compare the SBOM externalRef PURL with the VEX product @id."; exit 1; \
	fi
	@echo "=== VEX suppression proven to fire ==="
