ARG TARGETARCH

# Build the manager binary
FROM docker.io/library/golang:1.22 as builder

ARG TARGETARCH=amd64
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
FROM --platform=linux/$TARGETARCH registry.access.redhat.com/ubi9/ubi-minimal:9.4
WORKDIR /
COPY --from=builder /opt/app-root/bin/netobserv-ebpf-agent .
USER 65532:65532

ENTRYPOINT ["/netobserv-ebpf-agent"]
