package flows

import (
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

// Legacy implementations kept for old kernels.

func (m *Fetcher) legacyLookupAndDeleteMap(met *metrics.Metrics) map[ebpf.BpfFlowId]model.BpfFlowContent {
	flowMap := m.objects.AggregatedFlows

	iterator := flowMap.Iterate()
	var flows = make(map[ebpf.BpfFlowId]model.BpfFlowContent, m.config.CacheMaxFlows)
	var id ebpf.BpfFlowId
	var baseMetrics ebpf.BpfFlowMetrics
	count := 0

	// Deleting while iterating is really bad for performance (like, really!) as it causes seeing multiple times the same key
	// This is solved in >=4.20 kernels with LookupAndDelete
	for iterator.Next(&id, &baseMetrics) {
		count++
		if err := flowMap.Delete(id); err != nil {
			log.WithError(err).WithField("flowId", id).Warnf("couldn't delete flow entry")
			met.Errors.WithErrorName("flow-fetcher-legacy", "CannotDeleteFlows", metrics.HighSeverity).Inc()
		}
		flows[id] = model.NewBpfFlowContent(baseMetrics)
	}
	met.FlowBufferSizeGauge.WithBufferName("hashmap-legacy-total").Set(float64(count))
	met.FlowBufferSizeGauge.WithBufferName("hashmap-legacy-unique").Set(float64(len(flows)))

	m.ReadGlobalCounter(met)
	return flows
}
