package ebpf

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

// batchLookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
func (m *FlowFetcher) batchLookupAndDeleteMap(met *metrics.Metrics) map[BpfFlowId][]BpfFlowMetrics {
	flowMap := m.objects.AggregatedFlows

	var flows = make(map[BpfFlowId][]BpfFlowMetrics, m.cacheMaxSize)
	var metrics = make([]BpfFlowMetrics, m.cacheMaxSize*ebpf.MustPossibleCPU())
	var id BpfFlowId
	var ids = make([]BpfFlowId, m.cacheMaxSize)
	var cursor = ebpf.MapBatchCursor{}

	count := 0
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
		if err != nil {
			if errors.Is(err, ebpf.ErrNotSupported) {
				log.WithError(err).Warnf("switching to legacy mode")
				m.batchLookupAndDeleteSupported = false
				return m.LookupAndDeleteMap(met)
			}
			log.WithError(err).WithField("flowId", id).Warnf("couldn't delete flow entry")
			met.Errors.WithErrorName("flow-fetcher", "CannotDeleteFlows").Inc()
			continue
		}
	}

	met.BufferSizeGauge.WithBufferName("hashmap-total").Set(float64(count))
	met.BufferSizeGauge.WithBufferName("hashmap-unique").Set(float64(len(flows)))

	return flows
}

// batchLookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
func (p *PacketFetcher) batchLookupAndDeleteMap(met *metrics.Metrics) map[int][]*byte {
	packetMap := p.objects.PacketRecord
	packets := make(map[int][]*byte, p.cacheMaxSize)
	streams := make([]*byte, p.cacheMaxSize*ebpf.MustPossibleCPU())
	var id int
	var ids = make([]int, p.cacheMaxSize)
	var cursor = ebpf.MapBatchCursor{}

	for {
		count, err := packetMap.BatchLookupAndDelete(&cursor, ids, streams, nil)
		if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
			for i, id := range ids[:count] {
				for j := 0; j < ebpf.MustPossibleCPU(); j++ {
					packets[id] = append(packets[id], streams[i*ebpf.MustPossibleCPU()+j])
				}
			}

			break
		}
		if err != nil {
			if errors.Is(err, ebpf.ErrNotSupported) {
				log.WithError(err).Warnf("switching to legacy mode")
				p.batchLookupAndDeleteSupported = false
				return p.LookupAndDeleteMap(met)
			}
			log.WithError(err).WithField("flowId", id).Warnf("couldn't delete flow entry")
			met.Errors.WithErrorName("flow-fetcher", "CannotDeleteFlows").Inc()
			continue
		}
	}

	return packets
}
