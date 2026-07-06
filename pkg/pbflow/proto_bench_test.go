package pbflow

import (
	"net"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

// benchRecord builds a *model.Record equivalent to what MapTracer.evictFlows
// produces for a base IPv4 TCP flow with a single interface (the common,
// no-extra-features configuration).
func benchRecord(i int) *model.Record {
	var id ebpf.BpfFlowId
	src := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To16()
	dst := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i+1)).To16()
	copy(id.SrcIp[:], src)
	copy(id.DstIp[:], dst)
	id.SrcPort = uint16(1024 + (i % 60000))
	id.DstPort = 443
	id.TransportProtocol = 6

	now := time.Now()
	return &model.Record{
		ID: id,
		Metrics: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{
				StartMonoTimeTs: uint64(1_000_000 + i),
				EndMonoTimeTs:   uint64(2_000_000 + i),
				Bytes:           uint64(1500 * (1 + i%10)),
				Packets:         uint32(1 + i%10),
				EthProtocol:     0x0800,
				Flags:           0x10,
				SrcMac:          [6]uint8{0x02, 0, 0, 0, 0, 0x01},
				DstMac:          [6]uint8{0x02, 0, 0, 0, 0, 0x02},
			},
		},
		TimeFlowStart: now.Add(-time.Second),
		TimeFlowEnd:   now,
		AgentIP:       net.IPv4(10, 0, 0, 1),
		Interfaces: []model.IntfDirUdn{
			{Interface: "eth0", Direction: 0, Udn: ""},
		},
	}
}

// BenchmarkFlowToPB measures the per-flow protobuf conversion in the gRPC/Kafka
// export path. It runs once per flow per eviction, so its allocation profile
// directly affects the peak heap on busy nodes.
func BenchmarkFlowToPB(b *testing.B) {
	r := benchRecord(1)
	b.ReportAllocs()
	b.ResetTimer()
	var sink *Record
	for i := 0; i < b.N; i++ {
		sink = FlowToPB(r)
	}
	_ = sink
}

// BenchmarkFlowsToPB measures the full batch conversion of a realistic eviction
// batch (many records -> chunked *Records messages), matching sendBatch.
func BenchmarkFlowsToPB(b *testing.B) {
	const n = 10000
	batch := make([]*model.Record, n)
	for i := range batch {
		batch[i] = benchRecord(i)
	}
	const maxPerMsg = 10000 // GRPCMessageMaxFlows default
	b.ReportAllocs()
	b.ResetTimer()
	var sink []*Records
	for i := 0; i < b.N; i++ {
		sink = FlowsToPB(batch, maxPerMsg)
	}
	_ = sink
}
