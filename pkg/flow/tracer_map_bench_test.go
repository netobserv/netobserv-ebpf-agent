package flow

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

// benchFakeFetcher is an in-memory mapFetcher that returns a fresh copy of a
// pre-built flow map on each LookupAndDeleteMap call, so we can benchmark the
// userspace eviction/record-building cost in isolation from the kernel.
type benchFakeFetcher struct {
	flows map[ebpf.BpfFlowId]model.BpfFlowContent
}

func (f *benchFakeFetcher) LookupAndDeleteMap(_ *metrics.Metrics) map[ebpf.BpfFlowId]model.BpfFlowContent {
	// Return a copy: evictFlows consumes the map, and we want each iteration to
	// process the same population.
	out := make(map[ebpf.BpfFlowId]model.BpfFlowContent, len(f.flows))
	for k, v := range f.flows {
		out[k] = v
	}
	return out
}

func (f *benchFakeFetcher) DeleteMapsStaleEntries(_ time.Duration) {}

func benchBuildFlowMap(n, interfacesPerFlow int) map[ebpf.BpfFlowId]model.BpfFlowContent {
	m := make(map[ebpf.BpfFlowId]model.BpfFlowContent, n)
	for i := 0; i < n; i++ {
		var id ebpf.BpfFlowId
		src := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To16()
		dst := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i+1)).To16()
		copy(id.SrcIp[:], src)
		copy(id.DstIp[:], dst)
		id.SrcPort = uint16(1024 + (i % 60000))
		id.DstPort = 443
		id.TransportProtocol = 6
		flowMetrics := ebpf.BpfFlowMetrics{
			StartMonoTimeTs:  uint64(1_000_000 + i),
			EndMonoTimeTs:    uint64(2_000_000 + i),
			Bytes:            uint64(1500 * (1 + i%10)),
			Packets:          uint32(1 + i%10),
			EthProtocol:      0x0800,
			Flags:            0x10,
			SrcMac:           [6]uint8{0x02, 0, 0, 0, 0, 0x01},
			DstMac:           [6]uint8{0x02, 0, 0, 0, 0, 0x02},
			IfIndexFirstSeen: uint32(2 + i%4),
			NbObservedIntf:   uint8(interfacesPerFlow - 1),
		}
		for j := 0; j < interfacesPerFlow-1; j++ {
			flowMetrics.ObservedIntf[j] = uint32(10 + j)
			flowMetrics.ObservedDirection[j] = uint8(j % 2)
		}
		m[id] = model.NewBpfFlowContent(flowMetrics)
	}
	return m
}

// BenchmarkEvictFlows measures the full userspace eviction: reading the map and
// converting every entry into a *model.Record forwarded down the pipeline. This
// is the end-to-end per-eviction cost that drives peak heap on busy nodes.
//
// Sizes are chosen to bracket realistic CACHE_MAX_FLOWS values.
func BenchmarkEvictFlows(b *testing.B) {
	model.SetInterfaceNamer(func(ifIndex int, _ model.MacAddr) string {
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
	model.SetGlobalIP([]byte{10, 0, 0, 1})

	// Create the metrics and tracer once (NewMapTracer registers a histogram on
	// the global Prometheus registry, so constructing it per-size would emit
	// duplicate-registration warnings). We swap the fetcher's population per size.
	m := metrics.NoOp()
	fetcher := &benchFakeFetcher{}
	mt := NewMapTracer(fetcher, time.Hour, time.Hour, m, nil, false)

	for _, interfacesPerFlow := range []int{1, 3} {
		b.Run(interfaceCountName(interfacesPerFlow), func(b *testing.B) {
			for _, n := range []int{1000, 10000, 100000} {
				b.Run(sizeName(n), func(b *testing.B) {
					fetcher.flows = benchBuildFlowMap(n, interfacesPerFlow)
					out := make(chan []*model.Record, 1)
					ctx := context.Background()

					// Drain the output channel so evictFlows never blocks.
					done := make(chan struct{})
					go func() {
						for range out {
							continue // drain so evictFlows never blocks
						}
						close(done)
					}()

					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						mt.evictFlows(ctx, false, out)
					}
					b.StopTimer()
					close(out)
					<-done
				})
			}
		})
	}
}

func interfaceCountName(n int) string {
	if n == 1 {
		return "1-interface"
	}
	return strconv.Itoa(n) + "-interfaces"
}

func sizeName(n int) string {
	switch {
	case n >= 1000000:
		return "1M"
	case n >= 1000:
		return strconv.Itoa(n/1000) + "k"
	default:
		return strconv.Itoa(n)
	}
}
