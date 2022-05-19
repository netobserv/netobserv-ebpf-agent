# SW_VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the SW_VERSION as arg of the bundle target (e.g make bundle SW_VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export SW_VERSION=0.0.2)
SW_VERSION ?= main
BUILD_VERSION := $(shell git describe --long HEAD)
BUILD_DATE := $(shell date +%Y-%m-%d\ %H:%M)
BUILD_SHA := $(shell git rev-parse --short HEAD)

# In CI, to be replaced by `netobserv`
IMAGE_ORG ?= $(USER)

# IMAGE_TAG_BASE defines the namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
IMAGE_TAG_BASE ?= quay.io/$(IMAGE_ORG)/netobserv-ebpf-agent

# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):$(SW_VERSION)
IMG_SHA = $(IMAGE_TAG_BASE):$(BUILD_SHA)

LOCAL_GENERATOR_IMAGE ?= ebpf-generator:latest

CILIUM_EBPF_VERSION := v0.8.1
GOLANGCI_LINT_VERSION = v1.42.1

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
GOOS ?= linux
PROTOC_ARTIFACTS := pkg/pbflow

# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES="(/cmd/)|(bpf_bpfe)|(/examples/)|(/pkg/pbflow/)"

# Image building tool (docker / podman)
ifndef OCI_BIN
	ifeq (,$(shell which podman 2>/dev/null))
	OCI_BIN=docker
	else
	OCI_BIN=podman
	endif
endif

.PHONY: vendors
vendors:
	@echo "### Checking vendors"
	go mod tidy && go mod vendor

.PHONY: prereqs
prereqs:
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	test -f $(go env GOPATH)/bin/golangci-lint || GOFLAGS="" go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}
	test -f $(go env GOPATH)/bin/bpf2go || go install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}
	test -f $(go env GOPATH)/bin/protoc-gen-go || go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	test -f $(go env GOPATH)/bin/protoc-gen-go-grpc || go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	test -f $(go env GOPATH)/bin/kind || go install sigs.k8s.io/kind@latest

.PHONY: fmt
fmt: ## Run go fmt against code.
	@echo "### Formatting code"
	go fmt ./...

.PHONY: lint
lint: prereqs
	@echo "### Linting code"
	golangci-lint run ./...

# As generated artifacts are part of the code repo (pkg/ebpf and pkg/proto packages), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder or the
# protobuf definitions in the proto folder.
# You might want to use the docker-generate target instead of this.
.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: prereqs
	@echo "### Generating BPF Go bindings"
	go generate ./pkg/...
	@echo "### Generating gRPC and Protocol Buffers code"
	protoc --go_out=pkg --go-grpc_out=pkg proto/flow.proto

.PHONY: docker-generate
docker-generate:
	@echo "### Creating the container that generates the eBPF binaries"
	docker build . -f scripts/generators.Dockerfile -t $(LOCAL_GENERATOR_IMAGE)
	docker run --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: build
build: prereqs fmt lint test vendors compile

.PHONY: compile
compile:
	@echo "### Compiling project"
	GOOS=$(GOOS) go build -ldflags "-X main.version=${SW_VERSION} -X 'main.buildVersion=${BUILD_VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -mod vendor -a -o bin/netobserv-ebpf-agent cmd/netobserv-ebpf-agent.go

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

.PHONY: image-build
image-build: ## Build OCI image with the manager.
	$(OCI_BIN) build --build-arg SW_VERSION="$(SW_VERSION)" -t ${IMG} .

.PHONY: ci-images-build
ci-images-build: image-build
	$(OCI_BIN) build --build-arg BASE_IMAGE=$(IMG) -t $(IMG_SHA) -f scripts/shortlived.Dockerfile .

.PHONY: image-push
image-push: ## Push OCI image with the manager.
	$(OCI_BIN) push ${IMG}

.PHONY: tests-e2e
tests-e2e: prereqs
	$(OCI_BIN) build . -t ebpf-agent:test
	GOOS=$(GOOS) go test -v -mod vendor -tags e2e ./e2e/...

.PHONY: collect-e2e-logs
collect-e2e-logs:
	-rm -rf e2e-logs
	mkdir e2e-logs
	for folder in $$(find e2e -name test-logs); do mv $$folder/* collected-logs/ ; rm -rf $$folder; done