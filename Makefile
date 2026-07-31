SHELL := /bin/bash
GO ?= go
DIST ?= dist
TARGETS ?= linux/amd64

.PHONY: help fmt fmt-check vet lint shell-lint workflow-lint mod-check test test-race test-integration contract build package sbom verify clean tidy vulncheck secret-scan packaging-test

help:
	@echo "fmt              format the module"
	@echo "fmt-check        fail when the module is not formatted"
	@echo "vet              run go vet"
	@echo "shell-lint       run ShellCheck against packaging and build scripts"
	@echo "workflow-lint    validate GitHub Actions workflows"
	@echo "mod-check        verify the dependency graph and checksums"
	@echo "test             run unit and contract tests"
	@echo "test-race        run the race-sensitive tests"
	@echo "test-integration run the integration suite against a fake control plane"
	@echo "packaging-test   run install, upgrade, rollback and uninstall against a staged root"
	@echo "vulncheck        run govulncheck"
	@echo "secret-scan      scan the complete Git history for credentials"
	@echo "build            build the host binary into $(DIST)"
	@echo "package          build release tarballs, checksums and SBOMs for $(TARGETS)"
	@echo "verify           fmt-check, vet, test, contract and packaging tests"

fmt:
	$(GO) fmt ./...

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

lint: fmt-check vet shell-lint workflow-lint

shell-lint:
	bash build/quality/lint-shell.sh

workflow-lint:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -color=false .github/workflows/*.yml

mod-check:
	$(GO) mod verify
	@tmp="$$(mktemp -d)"; cp go.mod go.sum "$$tmp/"; status=0; $(GO) mod tidy || status=1; diff -u "$$tmp/go.mod" go.mod || status=1; diff -u "$$tmp/go.sum" go.sum || status=1; cp "$$tmp/go.mod" go.mod; cp "$$tmp/go.sum" go.sum; rm -rf "$$tmp"; exit "$$status"

test:
	CGO_ENABLED=1 $(GO) test ./cmd/... ./internal/... ./protocol/...

test-race:
	CGO_ENABLED=1 $(GO) test -race ./internal/... ./protocol/...

test-integration:
	CGO_ENABLED=1 $(GO) test ./test/integration/...

contract:
	CGO_ENABLED=1 $(GO) test ./protocol/...

packaging-test:
	bash test/packaging/run.sh

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

secret-scan:
	bash build/security/scan-secrets.sh

build:
	bash build/build.sh --binary-only --dist $(DIST)

package:
	bash build/build.sh --targets "$(TARGETS)" --dist $(DIST)

sbom: package

verify: lint mod-check test test-race contract test-integration packaging-test

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(DIST)
