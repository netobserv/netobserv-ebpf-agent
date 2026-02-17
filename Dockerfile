ARG TARGETARCH

# Build the manager binary
FROM docker.io/library/golang:1.25 as builder

ARG TARGETARCH

ARG LDFLAGS

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -ldflags "$LDFLAGS" -mod vendor -a -o bin/netobserv-ebpf-agent cmd/netobserv-ebpf-agent.go

# Create final image from minimal + built binary
FROM --platform=linux/$TARGETARCH registry.access.redhat.com/ubi9/ubi-minimal:9.7-1771346502
WORKDIR /
COPY --from=builder /opt/app-root/bin/netobserv-ebpf-agent .
USER 65532:65532

ENTRYPOINT ["/netobserv-ebpf-agent"]
