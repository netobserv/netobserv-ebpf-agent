package flows

import (
	"os"

	cilium "github.com/cilium/ebpf"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
)

func configureFlowMaps(spec *cilium.CollectionSpec, cfg *tracer.FetcherConfig, filter *attach.Filter) {
	netattach.ResizeMaps(spec, true, cfg.CacheMaxFlows, ebpf.FlowsBpfMapAggregatedFlows)
	netattach.ResizeMaps(spec, cfg.Flows.EnableDNSTracking, cfg.CacheMaxFlows, ebpf.FlowsBpfMapAggregatedFlowsDns)
	netattach.ResizeMaps(spec, cfg.Flows.EnableNetworkEventsMonitoring, cfg.CacheMaxFlows, ebpf.FlowsBpfMapAggregatedFlowsNetworkEvents)
	netattach.ResizeMaps(spec, cfg.Flows.EnablePktDrops, cfg.CacheMaxFlows, ebpf.FlowsBpfMapAggregatedFlowsPktDrop)
	netattach.ResizeMaps(spec, cfg.Flows.EnablePktTranslationTracking, cfg.CacheMaxFlows, ebpf.FlowsBpfMapAggregatedFlowsXlat)
	netattach.ResizeMaps(spec, cfg.Flows.EnableRTT || cfg.Flows.EnableIPsecTracking, cfg.CacheMaxFlows, ebpf.FlowsBpfMapAdditionalFlowMetrics)

	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableDNSTracking, 1, ebpf.FlowsBpfMapDnsFlows)
	netattach.MinimizeMapsIfDisabled(spec, filter != nil, 1, ebpf.FlowsBpfMapFilterMap, ebpf.FlowsBpfMapPeerFilterMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableIPsecTracking, 1, ebpf.FlowsBpfMapIpsecIngressMap, ebpf.FlowsBpfMapIpsecEgressMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.QUICTrackingMode == 1 || cfg.Flows.QUICTrackingMode == 2, 1, ebpf.FlowsBpfMapQuicFlows)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableFlowsRingbufFallback, os.Getpagesize(), ebpf.FlowsBpfMapDirectFlows)
}
