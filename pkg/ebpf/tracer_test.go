package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func BenchmarkFlowFetcher_LookupAndDeleteMap(b *testing.B) {
	var flowFetcherConfig = FlowFetcherConfig{
		EnableIngress: true,
		EnableEgress:  true,
		Debug:         false,
		Sampling:      1,
		CacheMaxSize:  100,
	}

	b.Run("BatchLookupAndDelete", func(b *testing.B) {
		m, err := NewFlowFetcher(&flowFetcherConfig)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			err = m.testBatchUpdateMap()
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
			m.testBatchLookupAndDeleteMap()
		}
	})

	b.Run("IterateLookupAndDelete", func(b *testing.B) {
		m, err := NewFlowFetcher(&flowFetcherConfig)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			err = m.testBatchUpdateMap()
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
			m.testIterateLookupAndDeleteMap()
		}
	})
}

func (m *FlowFetcher) testBatchUpdateMap() error {
	flowMap := m.objects.AggregatedFlows
	var ids = make([]BpfFlowId, m.cacheMaxSize)
	var metrics = make([]BpfFlowMetrics, m.cacheMaxSize*ebpf.MustPossibleCPU())

	for i := 0; i < m.cacheMaxSize; i++ {
		ids[i] = BpfFlowId{
			IfIndex: uint32(i),
		}
		for j := 0; j < ebpf.MustPossibleCPU(); j++ {
			metrics[i*ebpf.MustPossibleCPU()+j] = BpfFlowMetrics{
				Bytes:   uint64(10 * (i + j)),
				Packets: uint32(i + j),
			}
		}
	}

	_, err := flowMap.BatchUpdate(ids, metrics, nil)
	return err

}

func (m *FlowFetcher) testBatchLookupAndDeleteMap() map[BpfFlowId][]BpfFlowMetrics {
	flowMap := m.objects.AggregatedFlows

	var flows = make(map[BpfFlowId][]BpfFlowMetrics, m.cacheMaxSize)
	var metrics = make([]BpfFlowMetrics, m.cacheMaxSize*ebpf.MustPossibleCPU())
	var ids = make([]BpfFlowId, m.cacheMaxSize)
	var cursor = ebpf.MapBatchCursor{}

	for {
		count, err := flowMap.BatchLookupAndDelete(&cursor, ids, metrics, nil)
		if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
			for i, id := range ids[:count] {
				for j := 0; j < ebpf.MustPossibleCPU(); j++ {
					flows[id] = append(flows[id], metrics[i*ebpf.MustPossibleCPU()+j])
				}
			}

			break
		}
		if err != nil || count == 0 {
			log.Debugf("failed to use BatchLookupAndDelete api: %v fall back to use iterate and delete api", err)
			break
		}
	}

	return flows
}

func (m *FlowFetcher) testIterateLookupAndDeleteMap() map[BpfFlowId][]BpfFlowMetrics {
	flowMap := m.objects.AggregatedFlows

	var flows = make(map[BpfFlowId][]BpfFlowMetrics, m.cacheMaxSize)
	var metrics = make([]BpfFlowMetrics, m.cacheMaxSize)
	var id BpfFlowId
	var ids []BpfFlowId
	iterator := flowMap.Iterate()
	// First, get all ids and don't care about metrics (we need lookup+delete to be atomic)
	for iterator.Next(&id, &metrics) {
		ids = append(ids, id)
	}
	// Changing Iterate+Delete by LookupAndDelete would prevent some possible race conditions
	// TODO: detect whether LookupAndDelete is supported (Kernel>=4.20) and use it selectively
	for _, id := range ids {
		if err := flowMap.Delete(id); err != nil {
			log.WithError(err).WithField("flowId", id).
				Warnf("couldn't delete flow entry")
		}
		// We observed that eBFP PerCPU map might insert multiple times the same key in the map
		// (probably due to race conditions) so we need to re-join metrics again at userspace
		// TODO: instrument how many times the keys are is repeated in the same eviction
		flows[id] = append(flows[id], metrics...)
	}

	return flows
}
