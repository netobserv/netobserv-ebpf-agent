package flows

import (
	"os"

	cilium "github.com/cilium/ebpf"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
)

var mapToMetricName = map[string]string{
	ebpf.FlowsBpfMapAggregatedFlows:              metrics.MapNameFlows,
	ebpf.FlowsBpfMapAggregatedFlowsDns:           metrics.MapNameDNS,
	ebpf.FlowsBpfMapAggregatedFlowsNetworkEvents: metrics.MapNameNetEvents,
	ebpf.FlowsBpfMapAggregatedFlowsPktDrop:       metrics.MapNameDrops,
	ebpf.FlowsBpfMapAggregatedFlowsXlat:          metrics.MapNameXlat,
	ebpf.FlowsBpfMapAdditionalFlowMetrics:        metrics.MapNameAdditional,
	ebpf.FlowsBpfMapQuicFlows:                    metrics.MapNameQUIC,
}

func configureFlowMaps(spec *cilium.CollectionSpec, cfg *tracer.FetcherConfig, filter *attach.Filter, met *metrics.Metrics) {
	updater := func(name string, size int) {
		if label, ok := mapToMetricName[name]; ok {
			met.MapCapacityGauge.WithName(label).Set(float64(size))
		}
	}
	netattach.ResizeMaps(spec, true, cfg.CacheMaxFlows, updater, ebpf.FlowsBpfMapAggregatedFlows)
	netattach.ResizeMaps(spec, cfg.Flows.EnableDNSTracking, cfg.CacheMaxDNSFlows, updater, ebpf.FlowsBpfMapAggregatedFlowsDns)
	netattach.ResizeMaps(spec, cfg.Flows.EnableNetworkEventsMonitoring, cfg.CacheMaxNetworkEventFlows, updater, ebpf.FlowsBpfMapAggregatedFlowsNetworkEvents)
	netattach.ResizeMaps(spec, cfg.Flows.EnablePktDrops, cfg.CacheMaxPktDropsFlows, updater, ebpf.FlowsBpfMapAggregatedFlowsPktDrop)
	netattach.ResizeMaps(spec, cfg.Flows.EnablePktTranslationTracking, cfg.CacheMaxXlatFlows, updater, ebpf.FlowsBpfMapAggregatedFlowsXlat)
	netattach.ResizeMaps(spec, cfg.Flows.QUICTrackingMode == 1 || cfg.Flows.QUICTrackingMode == 2, cfg.CacheMaxQUICFlows, updater, ebpf.FlowsBpfMapQuicFlows)
	netattach.ResizeMaps(spec, cfg.Flows.EnableRTT || cfg.Flows.EnableIPsecTracking, cfg.CacheMaxAdditionalFlows, updater, ebpf.FlowsBpfMapAdditionalFlowMetrics)

	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableDNSTracking, 1, ebpf.FlowsBpfMapDnsFlows)
	netattach.MinimizeMapsIfDisabled(spec, filter != nil, 1, ebpf.FlowsBpfMapFilterMap, ebpf.FlowsBpfMapPeerFilterMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableIPsecTracking, 1, ebpf.FlowsBpfMapIpsecIngressMap, ebpf.FlowsBpfMapIpsecEgressMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableFlowsRingbufFallback, os.Getpagesize(), ebpf.FlowsBpfMapDirectFlows)
}
