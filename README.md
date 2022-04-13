# Network Observability eBPF Agent

Network Observability eBPF Agent.

## How to compile

```
make build
```

## How to run

```
sudo bin/netobserv-ebpf-agent
```
(Pod deployment will come soon)

## Development receipts

### How to regenerate the eBPF Kernel binaries

The eBPF program is embedded into the `pkg/ebpf/bpf_*` generated files.
This step is generally not needed unless you change the C code in the `bpf` folder.

If you have Docker installed, you just need to run:

```
make docker-generate
```

If you can't install docker, you should locally install the following required packages:

```
dnf install -y kernel-devel make llvm clang glibc-devel.i686
make generate
```

Tested in Fedora 35 and Red Hat Enterprise Linux 8.
