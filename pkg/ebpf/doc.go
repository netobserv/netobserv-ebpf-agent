// Package ebpf holds shared BPF name constants.
//
// Mode-specific bpf2go artifacts live in subpackages:
//
//   - pkg/ebpf/flows   — flow capture object (bpf/flows/flows.c)
//   - pkg/ebpf/packets — packet capture object (bpf/packets/packets.c)
//
// Map and program name consistency is checked by pkg/ebpf/symbols_test.go
// (run `make verify-maps`).
package ebpf
