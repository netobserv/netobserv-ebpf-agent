package model

import (
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

// BenchmarkNewRecord measures the per-flow cost of NewRecord, which runs once
// per flow on every cache eviction (up to CACHE_MAX_FLOWS times per interval).
// This is the single hottest allocation site in the common (grpc, no extra
// features) configuration.
func BenchmarkNewRecord(b *testing.B) {
	// Use a realistic interface namer (returns a stable string per ifindex)
	// rather than the default fmt.Sprintf-based placeholder.
	SetInterfaceNamer(func(ifIndex int, _ MacAddr) string {
		switch ifIndex {
		case 2:
			return "eth0"
		case 3:
			return "eth1"
		case 4:
			return "eth2"
		default:
			return "eth3"
		}
	})
	SetGlobalIP([]byte{10, 0, 0, 1})

	now := time.Now()
	mono := uint64(3_000_000)

	// Pre-build the metrics so we only measure NewRecord itself.
	contents := make([]BpfFlowContent, 1024)
	keys := make([]ebpf.BpfFlowId, 1024)
	for i := range contents {
		contents[i] = benchFlowContent(i)
		keys[i] = benchFlowID(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	var sink *Record
	for i := 0; i < b.N; i++ {
		idx := i & 1023
		sink = NewRecord(keys[idx], &contents[idx], now, mono, nil, nil)
	}
	_ = sink
}

// BenchmarkAccumulateBase measures the per-packet-batch merge that happens when
// a flow id already exists in the userspace accounter cache.
func BenchmarkAccumulateBase(b *testing.B) {
	base := benchFlowMetrics(1)
	other := benchFlowMetrics(2)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := base
		AccumulateBase(&p, &other)
	}
}
