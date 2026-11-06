GO ?= go
.PHONY: check fmt vet test build e2e packages clean
check: fmt vet test
fmt:
	@out=$$(gofmt -l $$(find . -path ./.tty59 -prune -o -name '*.go' -print)); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
vet:
	$(GO) vet ./...
test:
	$(GO) test -race -count=1 ./...
# VERSION: from the latest tag (v0.1.0 -> 0.1.0), or 0.0.0-dev. ARCHES: packaged architectures.
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || true)
VERSION := $(if $(VERSION),$(VERSION),0.0.0-dev)
ARCHES ?= amd64 arm64
NFPM ?= $(shell command -v nfpm 2>/dev/null || echo "$(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0")
LDFLAGS = -s -w -X github.com/nathabonfim59/segredium/internal/cli.Version=$(VERSION)
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/segredium ./cmd/segredium
# dist/: static binaries (tar.gz) plus .deb, .rpm and .apk per architecture, and checksums.
packages:
	@rm -rf dist bin/pkg && mkdir -p dist bin/pkg
	@set -e; for arch in $(ARCHES); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/pkg/segredium ./cmd/segredium; \
		tar -czf dist/segredium_$(VERSION)_linux_$$arch.tar.gz -C bin/pkg segredium -C ../.. LICENSE README.md; \
		for fmt in deb rpm apk; do \
			VERSION=$(VERSION) ARCH=$$arch $(NFPM) package -f packaging/nfpm.yaml -p $$fmt -t dist/; \
		done; \
	done
	cd dist && sha256sum * > SHA256SUMS
clean:
	rm -rf bin dist
e2e: build
	e2e/run.sh
