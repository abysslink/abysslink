# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors

BINARY     := abysslink
DAEMON     := abysslinkd
MODULE     := github.com/abysslink/abysslink
GO         ?= go
GOLANGCI   ?= golangci-lint
GORELEASER ?= goreleaser

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

## build: compile CLI and daemon binaries (reproducible: SOURCE_DATE_EPOCH from git)
build:
	SOURCE_DATE_EPOCH=$$(git log -1 --format='%ct') \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/abysslink
	SOURCE_DATE_EPOCH=$$(git log -1 --format='%ct') \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DAEMON) ./cmd/abysslinkd

## test: run all tests
test:
	$(GO) test -race -count=1 ./...

## lint: run golangci-lint and gofmt check
lint:
	$(GOLANGCI) run ./...
	@gofmt -l . | grep -v vendor | grep . && echo "gofmt: files need formatting (run gofmt -w .)" && exit 1 || true

## cover: run tests with coverage report
cover:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## release: build release artifacts via goreleaser (snapshot)
release:
	$(GORELEASER) release --snapshot --clean

## install: install CLI binary to GOPATH/bin or GOBIN
install:
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/abysslink

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
