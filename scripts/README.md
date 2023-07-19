# Scripts

## `update-bpf-headers.sh`

Fetches the BPF headers and places them in the `bpf/headers` folder. You don't need
to run this script unless you want to e.g. update any of them to a newer version.

## `generators.Dockerfile`

Dockerfile for the eBPF binaries and Protobuf implementation generator. It is invoked from the root
`Makefile`, in the `make docker-generate` target.
