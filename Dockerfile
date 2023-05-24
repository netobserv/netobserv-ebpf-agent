# We do not use --platform feature to auto fill this ARG because of incompatibility between podman and docker
ARG TARGETPLATFORM=linux/amd64
ARG BUILDPLATFORM=linux/amd64
ARG TARGETARCH=amd64

# Build the manager binary
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.19 as builder

ARG TARGETARCH
ARG TARGETPLATFORM
ARG VERSION="unknown"

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
COPY .mk/ .mk/

# Build
RUN GOARCH=$TARGETARCH make compile

# Create final image from minimal + built binary
FROM --platform=$TARGETPLATFORM registry.access.redhat.com/ubi9/ubi-minimal:9.1
WORKDIR /
COPY --from=builder /opt/app-root/bin/netobserv-ebpf-agent .
USER 65532:65532

ENTRYPOINT ["/netobserv-ebpf-agent"]
