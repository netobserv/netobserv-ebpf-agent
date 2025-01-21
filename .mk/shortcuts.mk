##@ shortcuts helpers

.PHONY: build
build: prereqs fmt lint test vendors compile ## Test and Build ebpf agent

.PHONY: build-image
build-image: image-build ## Build MULTIARCH_TARGETS images

.PHONY: push-image
push-image: image-push ## Push MULTIARCH_TARGETS images

.PHONY: build-manifest
build-manifest: manifest-build ## Build MULTIARCH_TARGETS manifest

.PHONY: push-manifest
push-manifest: manifest-push ## Push MULTIARCH_TARGETS manifest

.PHONY: images
images: image-build image-push manifest-build manifest-push ## Build and push MULTIARCH_TARGETS images and related manifest

.PHONY: bc-images
bc-images: bc-image-build bc-image-push bc-manifest-build bc-manifest-push ## Build and push MULTIARCH_TARGETS bytecode images and related manifest
