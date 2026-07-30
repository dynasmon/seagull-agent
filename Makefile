SHELL := /bin/bash
GO ?= go
DIST ?= dist
TARGETS ?= linux/amd64

.PHONY: help fmt fmt-check vet lint test test-race test-integration contract build package sbom verify clean tidy vulncheck packaging-test

help:
	@echo "fmt              format the module"
	@echo "fmt-check        fail when the module is not formatted"
	@echo "vet              run go vet"
	@echo "test             run unit and contract tests"
	@echo "test-race        run the race-sensitive tests"
	@echo "test-integration run the integration suite against a fake control plane"
	@echo "packaging-test   run install, upgrade, rollback and uninstall against a staged root"
	@echo "vulncheck        run govulncheck"
	@echo "build            build the host binary into $(DIST)"
	@echo "package          build release tarballs, checksums and SBOMs for $(TARGETS)"
	@echo "verify           fmt-check, vet, test, contract and packaging tests"

fmt:
	$(GO) fmt ./...

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

lint: fmt-check vet

test:
	CGO_ENABLED=1 $(GO) test ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race ./internal/spool/... ./internal/sender/... ./internal/enrollment/... ./internal/responseactions/... ./protocol/...

test-integration:
	CGO_ENABLED=1 $(GO) test -tags integration ./test/integration/...

contract:
	CGO_ENABLED=1 $(GO) test ./protocol/...

packaging-test:
	bash test/packaging/run.sh

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

build:
	bash build/build.sh --binary-only --dist $(DIST)

package:
	bash build/build.sh --targets "$(TARGETS)" --dist $(DIST)

sbom: package

verify: lint test contract test-integration packaging-test

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(DIST)
