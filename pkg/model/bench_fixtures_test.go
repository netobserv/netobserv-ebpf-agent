package model

import (
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
)

// This file provides shared fixtures for the memory hot-path benchmarks.
//
// These generators mirror the flows produced in the agent's default/common
// deployment (EXPORT=grpc, SAMPLING off, no DNS/RTT/drops/network-events/PCA/
// UDN/TLS features). They deliberately populate ONLY the base BpfFlowMetrics so
// the benchmarks measure the path that actually runs in that configuration.

// benchFlowID returns a synthetic, unique-ish flow id. Varying the low bytes of
// the IPs/ports by i keeps map keys distinct so cache/eviction benchmarks behave
// like a real high-cardinality node.
func benchFlowID(i int) ebpf.BpfFlowId {
	var id ebpf.BpfFlowId
	id.SrcId = uint32(i + 1)
	id.DstId = uint32(i + 1001)
	id.SrcPort = uint16(1024 + (i % 60000))
	id.DstPort = 443
	id.TransportProtocol = 6 // TCP
	return id
}

// benchFlowMetrics returns base metrics for an IPv4 TCP flow with a single
// interface observed (the overwhelmingly common case in production).
func benchFlowMetrics(i int) ebpf.BpfFlowMetrics {
	return ebpf.BpfFlowMetrics{
		StartMonoTimeTs:    uint64(1_000_000 + i),
		EndMonoTimeTs:      uint64(2_000_000 + i),
		Bytes:              uint64(1500 * (1 + i%10)),
		Packets:            uint32(1 + i%10),
		EthProtocol:        0x0800, // IPv4
		Flags:              0x10,   // ACK
		SrcMac:             [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMac:             [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		IfIndexFirstSeen:   uint32(2 + i%4),
		DirectionFirstSeen: uint8(i % 2),
		Dscp:               0,
		NbObservedIntf:     0,
	}
}

// benchFlowContent builds a BpfFlowContent for the given index. It is kept
// unexported and used only within this package's benchmarks; other packages
// build their own equivalent fixtures locally.
func benchFlowContent(i int) BpfFlowContent {
	return NewBpfFlowContent(benchFlowMetrics(i))
}
