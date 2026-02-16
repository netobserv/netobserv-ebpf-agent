# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= main

# Go architecture and targets images to build
GOARCH ?= amd64
MULTIARCH_TARGETS ?= amd64

# In CI, to be replaced by `netobserv`
IMAGE_ORG ?= $(USER)

# Image registry such as quay or docker
IMAGE_REGISTRY ?= quay.io

# IMAGE_TAG_BASE defines the namespace and part of the image name for remote images.
IMAGE_TAG_BASE ?= $(IMAGE_REGISTRY)/$(IMAGE_ORG)/netobserv-ebpf-agent

# Image URL to use all building/pushing image targets
IMAGE ?= $(IMAGE_TAG_BASE):$(VERSION)

# Image building tool (docker / podman) - docker is preferred in CI
OCI_BIN_PATH := $(shell which docker 2>/dev/null || which podman)
OCI_BIN ?= $(shell basename ${OCI_BIN_PATH})
OCI_BUILD_OPTS ?=

ifeq ("$(OCI_BIN)","docker")
# https://stackoverflow.com/questions/75521775/buildx-docker-image-claims-to-be-a-manifest-list
EXTRA_BUILD_FLAGS ?= --provenance=false
endif

ifneq ($(CLEAN_BUILD),)
	BUILD_DATE := $(shell date +%Y-%m-%d\ %H:%M)
	BUILD_SHA := $(shell git rev-parse --short HEAD)
	LDFLAGS ?= -X 'main.buildVersion=${VERSION}-${BUILD_SHA}' -X 'main.buildDate=${BUILD_DATE}'
endif

LOCAL_GENERATOR_IMAGE ?= ebpf-generator:latest
CILIUM_EBPF_VERSION := v0.19.0
GOLANGCI_LINT_VERSION = v2.8.0
GO_VERSION = 1.25.3
PROTOC_VERSION = 3.19.4
PROTOC_GEN_GO_VERSION="v1.35.1"
PROTOC_GEN_GO_GRPC_VERSION="v1.5.1"
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
	DOCKER_BUILDKIT=1 $(OCI_BIN) buildx build --load --build-arg LDFLAGS="${LDFLAGS}" --build-arg TARGETARCH=$(1) ${OCI_BUILD_OPTS} ${EXTRA_BUILD_FLAGS} -t ${IMAGE}-$(1) -f Dockerfile .;
endef

# push a single arch target image
define push_target
	echo 'pushing image ${IMAGE}-$(1)'; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) push ${IMAGE}-$(1);
endef

# manifest create a single arch target provided as argument
define manifest_add_target
	echo 'manifest add target $(1)'; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest add ${IMAGE} ${IMAGE}-$(1);
endef

# extract a single arch target binary
define extract_target
	echo 'extracting binary from ${IMAGE}-$(1)'; \
	$(OCI_BIN) create --name agent ${IMAGE}-$(1); \
	$(OCI_BIN) cp agent:/netobserv-ebpf-agent ./release-assets/netobserv-ebpf-agent-${VERSION}-linux-$(1); \
	$(OCI_BIN) rm -f agent;
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

.PHONY: install-protoc
install-protoc: ## Install protoc
	curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-linux-x86_64.zip -o protoc.zip
	unzip protoc.zip -d protoc && rm protoc.zip

.PHONY: prereqs
prereqs: ## Check if prerequisites are met, and install missing dependencies
	@echo "### Checking if prerequisites are met, and installing missing dependencies"
	test -f ./bin/golangci-lint-${GOLANGCI_LINT_VERSION} || ( \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s ${GOLANGCI_LINT_VERSION} \
		&& mv ./bin/golangci-lint ./bin/golangci-lint-${GOLANGCI_LINT_VERSION})
	test -f $(shell go env GOPATH)/bin/bpf2go || go install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}
	test -f $(shell go env GOPATH)/bin/protoc-gen-go || go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}
	test -f $(shell go env GOPATH)/bin/protoc-gen-go-grpc || go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}
	test -f $(shell go env GOPATH)/bin/kind || go install sigs.k8s.io/kind@latest
	test "$(shell PATH="$$(pwd)/protoc/bin:$$PATH" && protoc --version)" = "libprotoc $(PROTOC_VERSION)" || $(MAKE) install-protoc

##@ Develop

.PHONY: fmt
fmt: ## Run go fmt against code.
	@echo "### Formatting code"
	go fmt ./...
	find ./bpf -type f -not -path "./bpf/headers/*" -name "*.[ch]" | xargs clang-format -i --Werror

.PHONY: lint
lint: prereqs ## Lint the code
	@echo "### Linting golang code"
	./bin/golangci-lint-${GOLANGCI_LINT_VERSION} run --timeout 3m ./...
	@echo "### Linting bpf C code"
	find ./bpf -type f -not -path "./bpf/headers/*" -name "*.[ch]" | xargs clang-format --dry-run --Werror

.PHONY: gen-bpf
gen-bpf: export BPF_CLANG := $(CLANG)
gen-bpf: export BPF_CFLAGS := $(CFLAGS)
gen-bpf: prereqs ## Generate BPF (pkg/ebpf package)
	@echo "### Generating BPF Go bindings"
	go generate ./pkg/...

.PHONY: gen-protobuf
gen-protobuf: prereqs ## Generate protocol buffer (pkg/proto package)
	@echo "### Generating gRPC and Protocol Buffers code"
	PATH="$(shell pwd)/protoc/bin:$$PATH" protoc --go_out=pkg --go-grpc_out=pkg proto/flow.proto
	PATH="$(shell pwd)/protoc/bin:$$PATH" protoc --go_out=pkg --go-grpc_out=pkg proto/packet.proto

# As generated artifacts are part of the code repo (pkg/ebpf and pkg/proto packages), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder or the
# protobuf definitions in the proto folder.
# You might want to use the docker-generate target instead of this.
.PHONY: generate
generate: gen-bpf gen-protobuf

.PHONY: docker-generate
docker-generate: ## Create the container that generates the eBPF binaries
	@echo "### Creating the container that generates the eBPF binaries"
	$(OCI_BIN) buildx build . -f scripts/generators.Dockerfile -t $(LOCAL_GENERATOR_IMAGE) --platform=linux/amd64 --build-arg EXTENSION="x86_64" --build-arg PROTOCVERSION="$(PROTOC_VERSION)" --build-arg GOVERSION="$(GO_VERSION)" --load
	$(OCI_BIN) run --privileged --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: compile
compile: ## Compile ebpf agent project
	@echo "### Compiling project"
	GOARCH=${GOARCH} GOOS=$(GOOS) go build -mod vendor -o bin/netobserv-ebpf-agent cmd/netobserv-ebpf-agent.go

.PHONY: test
test: ## Test code using go test
	@echo "### Testing code"
	GOOS=$(GOOS) go test -mod vendor ./pkg/... ./cmd/... -coverpkg=./... -coverprofile cover.all.out

.PHONY: verify-maps
verify-maps: ## Verify map names consistency across all sources
	@echo "### Verifying map names consistency"
	go test -v ./pkg/maps

.PHONY: test-race
test-race: ## Test code using go test -race
	@echo "### Testing code for race conditions"
	GOOS=$(GOOS) go test -race -mod vendor ./pkg/... ./cmd/...

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
	rm -f ebpf-agent.tar || true
	$(OCI_BIN) build . --build-arg LDFLAGS="" --build-arg TARGETARCH=$(GOARCH) -t localhost/ebpf-agent:test
	$(OCI_BIN) save -o ebpf-agent.tar localhost/ebpf-agent:test
	GOOS=$(GOOS) go test -p 1 -timeout 30m -v -mod vendor -tags e2e ./e2e/...

.PHONY: create-and-deploy-kind-cluster
create-and-deploy-kind-cluster: prereqs ## Create a kind cluster and deploy the agent.
	scripts/kind-cluster.sh

.PHONY: destroy-kind-cluster
destroy-kind-cluster: ## Destroy the kind cluster.
	kubectl delete -f scripts/agent.yml
	kind delete cluster

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
	echo 'building manifest $(IMAGE)'
	DOCKER_BUILDKIT=1 $(OCI_BIN) rmi ${IMAGE} -f
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest create ${IMAGE} $(foreach target,$(MULTIARCH_TARGETS), --amend ${IMAGE}-$(target));

.PHONY: manifest-push
manifest-push: ## Push MULTIARCH_TARGETS manifest
	@echo 'publish manifest $(IMAGE)'
ifeq (${OCI_BIN}, docker)
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${IMAGE};
else
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${IMAGE} docker://${IMAGE};
endif

.PHONY: extract-binaries
extract-binaries: ## Extract all MULTIARCH_TARGETS binaries
	trap 'exit' INT; \
	mkdir -p release-assets; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call extract_target,$(target)))

include .mk/bc.mk
include .mk/shortcuts.mk
