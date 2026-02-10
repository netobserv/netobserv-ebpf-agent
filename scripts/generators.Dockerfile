FROM fedora:44

ARG GOVERSION="1.25.3"
ARG PROTOCVERSION
ARG TARGETARCH="amd64"
ARG EXTENSION

RUN echo "zchunk=false" >> /etc/dnf/dnf.conf

RUN echo "using TARGETARCH: $TARGETARCH EXTENSION: $EXTENSION"
RUN dnf clean all && rm -rf /var/cache/* && \
    dnf install -y git kernel-devel make llvm clang unzip

# Installs dependencies that are required to compile eBPF programs
RUN dnf install -y git kernel-devel make llvm clang unzip
RUN dnf clean all

VOLUME ["/src"]

WORKDIR /

# Installs a fairly modern distribution of Go
RUN curl -fSL https://go.dev/dl/go$GOVERSION.linux-$TARGETARCH.tar.gz -o go.tar.gz && \
    tar -xzf go.tar.gz && rm go.tar.gz

ENV GOROOT /go
RUN mkdir -p /gopath
ENV GOPATH /gopath
RUN mkdir -p /protoc
WORKDIR /protoc

# Installs Protoc compiler
RUN curl -fSL https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOCVERSION/protoc-${PROTOCVERSION}-linux-${EXTENSION}.zip -o protoc.zip && \
    unzip protoc.zip && rm protoc.zip

ENV PATH $GOROOT/bin:$GOPATH/bin:/protoc/bin:$PATH

WORKDIR /tmp
# Copies some pre-required Go dependencies to avoid downloading them on each build
COPY Makefile Makefile
COPY .mk/ .mk/
RUN make prereqs

WORKDIR /src
RUN git config --global --add safe.directory '*'

ENTRYPOINT ["make", "generate"]

