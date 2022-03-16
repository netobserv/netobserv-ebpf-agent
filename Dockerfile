# Build the manager binary
FROM registry.access.redhat.com/ubi8/go-toolset:1.16.7-5 as builder
ARG VERSION="unknown"
ARG GOVERSION="1.17.8"

WORKDIR /opt/app-root

# TEMPORARY STEPS UNTIL ubi8 releases a go1.17 image
RUN wget -q https://go.dev/dl/go$GOVERSION.linux-amd64.tar.gz && tar -xzf go$GOVERSION.linux-amd64.tar.gz
ENV GOROOT /opt/app-root/go
RUN mkdir -p /opt/app-root/gopath
ENV GOPATH /opt/app-root/gopath
ENV PATH $GOROOT/bin:$GOPATH/bin:$PATH
WORKDIR /opt/app-root/src
# END OF LINES TO REMOVE

# Copy the go manifests and source
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile

# Build
RUN make build

# Create final image from minimal + built binary
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.5-204
WORKDIR /
COPY --from=builder /opt/app-root/src/bin/netobserv-agent .
USER 65532:65532

ENTRYPOINT ["/netobserv-agent"]
