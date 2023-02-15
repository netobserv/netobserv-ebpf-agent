# Build the manager binary
FROM docker.io/library/golang:1.19 as builder

ARG SW_VERSION="unknown"

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

# Build
RUN make compile

# Create final image from minimal + built binary
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.1
WORKDIR /
COPY --from=builder /opt/app-root/bin/netobserv-ebpf-agent .
USER 65532:65532

ENTRYPOINT ["/netobserv-ebpf-agent"]
