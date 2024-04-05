# We do not use --platform feature to auto fill this ARG because of incompatibility between podman and docker
ARG TARGETPLATFORM=linux/amd64
ARG BUILDPLATFORM=linux/amd64
ARG TARGETARCH=amd64
ARG GOVERSION="1.21.7"

# Build layer
FROM --platform=$TARGETPLATFORM fedora:39 as builder
ARG TARGETARCH
ARG TARGETPLATFORM
ARG GOVERSION
ARG VERSION="unknown"

RUN dnf install -y git go kernel-devel make llvm clang unzip
RUN dnf clean all

WORKDIR /

RUN curl -qL https://go.dev/dl/go$GOVERSION.linux-$TARGETARCH.tar.gz -o go.tar.gz
RUN tar -xzf go.tar.gz
RUN rm go.tar.gz

ENV GOROOT /go
RUN mkdir -p /gopath
ENV GOPATH /gopath
ENV PATH $GOROOT/bin:$GOPATH/bin:$PATH

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
RUN make gen-bpf
RUN GOARCH=$TARGETARCH make compile

# Create final image from minimal + built binary
FROM --platform=$TARGETPLATFORM registry.access.redhat.com/ubi9/ubi-minimal:9.3
WORKDIR /
COPY --from=builder /opt/app-root/bin/netobserv-ebpf-agent .
USER 65532:65532

ENTRYPOINT ["/netobserv-ebpf-agent"]
