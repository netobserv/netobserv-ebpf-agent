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
	netattach.ResizeMaps(spec, true, cfg.CacheMaxFlows, ebpf.BpfMapAggregatedFlows)
	netattach.ResizeMaps(spec, cfg.Flows.EnableDNSTracking, cfg.CacheMaxFlows, ebpf.BpfMapAggregatedFlowsDns)
	netattach.ResizeMaps(spec, cfg.Flows.EnableNetworkEventsMonitoring, cfg.CacheMaxFlows, ebpf.BpfMapAggregatedFlowsNetworkEvents)
	netattach.ResizeMaps(spec, cfg.Flows.EnablePktDrops, cfg.CacheMaxFlows, ebpf.BpfMapAggregatedFlowsPktDrop)
	netattach.ResizeMaps(spec, cfg.Flows.EnablePktTranslationTracking, cfg.CacheMaxFlows, ebpf.BpfMapAggregatedFlowsXlat)
	netattach.ResizeMaps(spec, cfg.Flows.EnableRTT || cfg.Flows.EnableIPsecTracking, cfg.CacheMaxFlows, ebpf.BpfMapAdditionalFlowMetrics)

	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableDNSTracking, 1, ebpf.BpfMapDnsFlows)
	netattach.MinimizeMapsIfDisabled(spec, filter != nil, 1, ebpf.BpfMapFilterMap, ebpf.BpfMapPeerFilterMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableIPsecTracking, 1, ebpf.BpfMapIpsecIngressMap, ebpf.BpfMapIpsecEgressMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.QUICTrackingMode == 1 || cfg.Flows.QUICTrackingMode == 2, 1, ebpf.BpfMapQuicFlows)
	netattach.MinimizeMapsIfDisabled(spec, cfg.EnableOpenSSLTracking, 1, ebpf.BpfMapSslReadActiveMap, ebpf.BpfMapSslFdMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.EnableOpenSSLTracking, os.Getpagesize(), ebpf.BpfMapSslDataEventMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.Flows.EnableFlowsRingbufFallback, os.Getpagesize(), ebpf.BpfMapDirectFlows)
}
