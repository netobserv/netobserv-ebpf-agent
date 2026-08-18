package packets

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64,ppc64le,s390x Packets ../../../bpf/packets/packets.c -- -I../../../bpf/headers -I../../../bpf -I../../../bpf/packets
