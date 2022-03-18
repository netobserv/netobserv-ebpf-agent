# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= main

# IMAGE_TAG_BASE defines the namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
IMAGE_TAG_BASE ?= quay.io/netobserv/netobserv-agent

# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):$(VERSION)

LOCAL_GENERATOR_IMAGE ?= ebpf-generator:latest

CILIUM_EBPF_VERSION := v0.8.1
GOLANGCI_LINT_VERSION = v1.42.1

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
GOOS := linux
PROTOC_ARTIFACTS := pkg/pbflow

# Image building tool (docker / podman)
ifeq (,$(shell which podman 2>/dev/null))
OCI_BIN=docker
else
OCI_BIN=podman
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
	test -f $(go env GOPATH)/bin/protoc-gen-go-grpc || go install  google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

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
	protoc --go_out=export/pkg --go-grpc_out=export/pkg export/proto/flow.proto

.PHONY: docker-generate
docker-generate:
	@echo "### Creating the container that generates the eBPF binaries"
	docker build . -f scripts/Dockerfile_generators -t $(LOCAL_GENERATOR_IMAGE)
	docker run --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: build
build: prereqs fmt lint test compile

.PHONY: compile
compile:
	@echo "### Compiling project"
	GOOS=$(GOOS) go build -ldflags "-X main.version=${VERSION}" -mod vendor -a -o bin/netobserv-agent cmd/netobserv-agent.go

.PHONY: test
test:
	@echo "### Testing code"
	GOOS=$(GOOS) go test -mod vendor -a ./... -coverpkg=./... -coverprofile cover.out

.PHONY: coverage-report
coverage-report:
	@echo "### Generating coverage report"
	go tool cover --func=./cover.out

.PHONY: coverage-report-html
coverage-report-html:
	@echo "### Generating HTML coverage report"
	go tool cover --html=./cover.out

image-build: test ## Build OCI image with the manager.
	$(OCI_BIN) build --build-arg VERSION="$(VERSION)" -t ${IMG} .

image-push: ## Push OCI image with the manager.
	$(OCI_BIN) push ${IMG}