FROM fedora:35

ARG GOVERSION="1.21.3"
ARG PROTOCVERSION="3.19.4"

# Installs dependencies that are required to compile eBPF programs
RUN dnf install -y kernel-devel make llvm clang glibc-devel.i686 unzip
RUN dnf clean all

VOLUME ["/src"]

WORKDIR /

# Installs a fairly modern distribution of Go
RUN curl -qL https://go.dev/dl/go$GOVERSION.linux-amd64.tar.gz -o go.tar.gz
RUN tar -xzf go.tar.gz
RUN rm go.tar.gz

ENV GOROOT /go
RUN mkdir -p /gopath
ENV GOPATH /gopath

RUN mkdir -p /protoc
WORKDIR /protoc

# Installs Protoc compiler
RUN curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOCVERSION/protoc-${PROTOCVERSION}-linux-x86_64.zip -o protoc.zip
RUN unzip protoc.zip
RUN rm protoc.zip

ENV PATH $GOROOT/bin:$GOPATH/bin:/protoc/bin:$PATH

WORKDIR /tmp
# Copies some pre-required Go dependencies to avoid downloading them on each build
COPY Makefile Makefile
COPY .mk/ .mk/
RUN make prereqs

WORKDIR /src

ENTRYPOINT ["make", "generate"]

