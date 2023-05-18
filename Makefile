# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= main
BUILD_DATE := $(shell date +%Y-%m-%d\ %H:%M)
TAG_COMMIT := $(shell git rev-list --abbrev-commit --tags --max-count=1)
TAG := $(shell git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)
BUILD_SHA := $(shell git rev-parse --short HEAD)
BUILD_VERSION := $(TAG:v%=%)
ifneq ($(COMMIT), $(TAG_COMMIT))
	BUILD_VERSION := $(BUILD_VERSION)-$(BUILD_SHA)
endif
ifneq ($(shell git status --porcelain),)
	BUILD_VERSION := $(BUILD_VERSION)-dirty
endif

# Go architecture and targets images to build
GOARCH ?= amd64
MULTIARCH_TARGETS ?= amd64 arm64 ppc64le

# In CI, to be replaced by `netobserv`
IMAGE_ORG ?= $(USER)

# IMAGE_TAG_BASE defines the namespace and part of the image name for remote images.
IMAGE_TAG_BASE ?= quay.io/$(IMAGE_ORG)/netobserv-ebpf-agent

# Image URL to use all building/pushing image targets
IMAGE ?= $(IMAGE_TAG_BASE):$(VERSION)
IMAGE_SHA = $(IMAGE_TAG_BASE):$(BUILD_SHA)

# Image building tool (docker / podman)
OCI_BIN_PATH := $(shell which podman  || which docker)
OCI_BIN ?= $(shell v='$(OCI_BIN_PATH)'; echo "$${v##*/}")

LOCAL_GENERATOR_IMAGE ?= ebpf-generator:latest
CILIUM_EBPF_VERSION := v0.10.0
GOLANGCI_LINT_VERSION = v1.50.1
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
GOOS ?= linux
PROTOC_ARTIFACTS := pkg/pbflow
# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES="(/cmd/)|(bpf_bpfe)|(/examples/)|(/pkg/pbflow/)"

.DEFAULT_GOAL := help

# build a single arch target provided as argument
define build_target
	echo 'building image for arch $(1)'; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) buildx build --load --build-arg TARGETPLATFORM=linux/$(1) --build-arg TARGETARCH=$(1) --build-arg BUILDPLATFORM=linux/amd64 -t ${IMAGE}-$(1) -f Dockerfile .;
endef

# push a single arch target image
define push_target
	echo 'pushing image ${IMAGE}-$(1)'; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) push ${IMAGE}-$(1);
endef

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: vendors
vendors: ## Check go vendors
	@echo "### Checking vendors"
	go mod tidy && go mod vendor

.PHONY: prereqs
prereqs: ## Check if prerequisites are met, and install missing dependencies
	@echo "### Checking if prerequisites are met, and installing missing dependencies"
	test -f $(shell go env GOPATH)/bin/golangci-lint || GOFLAGS="" go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}
	test -f $(shell go env GOPATH)/bin/bpf2go || go install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}
	test -f $(shell go env GOPATH)/bin/protoc-gen-go || go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	test -f $(shell go env GOPATH)/bin/protoc-gen-go-grpc || go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	test -f $(shell go env GOPATH)/bin/kind || go install sigs.k8s.io/kind@latest

##@ Develop

.PHONY: fmt
fmt: ## Run go fmt against code.
	@echo "### Formatting code"
	go fmt ./...

.PHONY: lint
lint: prereqs ## Lint the code
	@echo "### Linting code"
	golangci-lint run ./... --timeout=3m

# As generated artifacts are part of the code repo (pkg/ebpf and pkg/proto packages), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder or the
# protobuf definitions in the proto folder.
# You might want to use the docker-generate target instead of this.
.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: prereqs ## Generate artifacts of the code repo (pkg/ebpf and pkg/proto packages)
	@echo "### Generating BPF Go bindings"
	go generate ./pkg/...
	@echo "### Generating gRPC and Protocol Buffers code"
	protoc --go_out=pkg --go-grpc_out=pkg proto/flow.proto

.PHONY: docker-generate
docker-generate: ## Create the container that generates the eBPF binaries
	@echo "### Creating the container that generates the eBPF binaries"
	$(OCI_BIN) build . -f scripts/generators.Dockerfile -t $(LOCAL_GENERATOR_IMAGE)
	$(OCI_BIN) run --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: compile
compile: ## Compile ebpf agent project
	@echo "### Compiling project"
	GOARCH=${GOARCH} GOOS=$(GOOS) go build -ldflags "-X main.version=${VERSION} -X 'main.buildVersion=${BUILD_VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -mod vendor -a -o bin/netobserv-ebpf-agent cmd/netobserv-ebpf-agent.go

.PHONY: test
test: ## Test code using go test
	@echo "### Testing code"
	GOOS=$(GOOS) go test -mod vendor -a ./... -coverpkg=./... -coverprofile cover.all.out

.PHONY: cov-exclude-generated
cov-exclude-generated:
	grep -vE "(/cmd/)|(bpf_bpfe)|(/examples/)|(/pkg/pbflow/)" cover.all.out > cover.out

.PHONY: coverage-report
coverage-report: cov-exclude-generated ## Generate coverage report
	@echo "### Generating coverage report"
	go tool cover --func=./cover.out

.PHONY: coverage-report-html
coverage-report-html: cov-exclude-generated ## Generate HTML coverage report
	@echo "### Generating HTML coverage report"
	go tool cover --html=./cover.out

.PHONY: tests-e2e
.ONESHELL:
tests-e2e: prereqs ## Run e2e tests
	go clean -testcache
	# making the local agent image available to kind in two ways, so it will work in different
	# environments: (1) as image tagged in the local repository (2) as image archive.
	$(OCI_BIN) build . -t localhost/ebpf-agent:test
	$(OCI_BIN) save -o ebpf-agent.tar localhost/ebpf-agent:test
	GOOS=$(GOOS) go test -p 1 -timeout 30m -v -mod vendor -tags e2e ./e2e/...

##@ Images

# note: to build and push custom image tag use: IMAGE_ORG=myuser VERSION=dev s
.PHONY: image-build
image-build: ## Build MULTIARCH_TARGETS images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call build_target,$(target)))

.PHONY: image-push
image-push: ## Push MULTIARCH_TARGETS images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call push_target,$(target)))

.PHONY: manifest-build
manifest-build: ## Build MULTIARCH_TARGETS manifest
	@echo 'building manifest $(IMAGE)'
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest create ${IMAGE} $(foreach target,$(MULTIARCH_TARGETS),--amend ${IMAGE}-$(target));

.PHONY: manifest-push
manifest-push: ## Push MULTIARCH_TARGETS manifest
	@echo 'publish manifest $(IMAGE)'
ifeq (${OCI_BIN}, docker)
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${IMAGE};
else
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${IMAGE} docker://${IMAGE};
endif

.PHONY: ci-manifest-build
ci-manifest-build: manifest-build ## Build CI manifest
	$(OCI_BIN) build --build-arg BASE_IMAGE=$(IMAGE) -t $(IMAGE_SHA) -f scripts/shortlived.Dockerfile .
ifeq ($(VERSION), main)
# Also tag "latest" only for branch "main"
	$(OCI_BIN) build -t $(IMAGE) -t $(IMAGE_TAG_BASE):latest -f scripts/shortlived.Dockerfile .
endif

.PHONY: ci-manifest-push
ci-manifest-push: ## Push CI manifest
	$(OCI_BIN) push $(IMAGE_SHA)
ifeq ($(VERSION), main)
# Also tag "latest" only for branch "main"
	$(OCI_BIN) push ${IMAGE}
	$(OCI_BIN) push $(IMAGE_TAG_BASE):latest
endif

include .mk/shortcuts.mk
