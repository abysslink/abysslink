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

.PHONY: build test lint cover release install clean

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
