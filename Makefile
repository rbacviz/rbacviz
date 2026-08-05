BINARY := rbacviz
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIRTY ?= $(shell test -z "$$(git status --porcelain 2>/dev/null)" && printf false || printf true)
LDFLAGS := -s -w \
	-X main.buildVersion=$(VERSION) \
	-X main.buildCommit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE) \
	-X main.buildDirty=$(DIRTY)

.PHONY: build test verify lint vuln cross-build screenshots release verify-reproducible clean

build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/rbacviz

test:
	go test -race ./...

lint:
	golangci-lint run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

verify:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

cross-build:
	./hack/build-all.sh

screenshots:
	go run ./hack/render-screenshots

release:
	test -n "$(VERSION)"
	test -n "$(COMMIT)"
	test -n "$(SOURCE_DATE_EPOCH)"
	go run ./hack/release --version "$(VERSION)" --commit "$(COMMIT)" --source-date-epoch "$(SOURCE_DATE_EPOCH)"

verify-reproducible:
	test -n "$(VERSION)"
	test -n "$(COMMIT)"
	test -n "$(SOURCE_DATE_EPOCH)"
	./hack/verify-reproducible.sh "$(VERSION)" "$(COMMIT)" "$(SOURCE_DATE_EPOCH)"

clean:
	rm -rf bin dist
