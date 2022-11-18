SW_VERSION ?= main
BUILD_VERSION := $(shell git describe --long HEAD)
BUILD_DATE := $(shell date +%Y-%m-%d\ %H:%M)
BUILD_SHA := $(shell git rev-parse --short HEAD)

CILIUM_EBPF_VERSION := v0.8.1
GOLANGCI_LINT_VERSION = v1.46.2

GOOS ?= linux

# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES="(/cmd/)|(bpf_bpfe)|(/examples/)|(/pkg/pbflow/)"

.PHONY: vendors
vendors:
	@echo "### Checking vendors"
	go mod tidy && go mod vendor

.PHONY: fmt
fmt: ## Run go fmt against code.
	@echo "### Formatting code"
	go fmt ./...

.PHONY: prereqs
prereqs:
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	test -f $(shell go env GOPATH)/bin/golangci-lint || GOFLAGS="" go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}

.PHONY: lint
lint: prereqs
	@echo "### Linting code"
	golangci-lint run ./... --timeout=3m

.PHONY: build
build: fmt vendors lint test compile

.PHONY: compile
compile:
	@echo "### Compiling project"
	GOOS=$(GOOS) go build --buildmode=plugin -ldflags "-X main.version=${SW_VERSION} -X 'main.buildVersion=${BUILD_VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -mod vendor -a -o ../../bin/plugins/grpc.so ./...

.PHONY: test
test:
	@echo "### Testing code"
	GOOS=$(GOOS) go test -mod vendor -a ./... -coverpkg=./... -coverprofile cover.all.out

.PHONY: cov-exclude-generated
cov-exclude-generated:
	grep -vE "(/cmd/)|(bpf_bpfe)|(/examples/)|(/pkg/pbflow/)" cover.all.out > cover.out

.PHONY: coverage-report
coverage-report: cov-exclude-generated
	@echo "### Generating coverage report"
	go tool cover --func=./cover.out

.PHONY: coverage-report-html
coverage-report-html: cov-exclude-generated
	@echo "### Generating HTML coverage report"
	go tool cover --html=./cover.out

