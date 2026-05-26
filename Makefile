# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors

BINARY     := abysslink
DAEMON     := abysslinkd
MODULE     := github.com/abysslink/abysslink
GO         ?= go
GOLANGCI   ?= golangci-lint
GORELEASER ?= goreleaser

# Build info
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS    := -s -w \
  -X $(MODULE)/internal/cli.version=$(VERSION) \
  -X $(MODULE)/internal/cli.commit=$(COMMIT) \
  -X $(MODULE)/internal/cli.buildDate=$(BUILD_DATE)

.PHONY: build test lint cover release install clean conformance security-audit

## build: compile CLI and daemon binaries
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/abysslink
	$(GO) build -ldflags "$(LDFLAGS)" -o $(DAEMON) ./cmd/abysslinkd

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
	$(GO) install -ldflags "$(LDFLAGS)" ./cmd/abysslink

## clean: remove build artifacts
clean:
	rm -f $(BINARY) $(DAEMON) coverage.out coverage.html
	rm -rf dist/

## conformance: build and run the end-to-end conformance test suite
conformance: build
	$(GO) run ./cmd/abysslink-conformance

## security-audit: grep for leaked secrets, check binary size, verify no telemetry
security-audit:
	@echo "=== Security Audit ==="
	@echo "--- Checking for secrets in audit log ---"
	@! grep -rE '(secret|token|password|api_key)["\s:=]+[a-zA-Z0-9+/]{20,}' \
		"$${HOME}/.local/state/abysslink/audit.log" 2>/dev/null \
		&& echo "OK: no secrets found in audit log" \
		|| echo "WARN: possible secrets in audit log (review manually)"
	@echo "--- Checking binary size (limit: 50 MB) ---"
	@if [ -f "$(BINARY)" ]; then \
		size=$$(stat -f%z "$(BINARY)" 2>/dev/null || stat -c%s "$(BINARY)" 2>/dev/null); \
		limit=$$((50 * 1024 * 1024)); \
		if [ "$$size" -gt "$$limit" ]; then \
			echo "FAIL: $(BINARY) is $$(du -sh $(BINARY) | cut -f1), exceeds 50 MB"; exit 1; \
		else \
			echo "OK: $(BINARY) is $$(du -sh $(BINARY) | cut -f1)"; \
		fi; \
	else \
		echo "SKIP: $(BINARY) not built (run make build first)"; \
	fi
	@echo "--- Checking for telemetry imports ---"
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
