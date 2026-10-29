package flows

import (
	"os"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureFlowMaps(t *testing.T) {
	for _, tc := range []struct {
		name             string
		features         configflows.Features
		openssl, filter  bool
		cached, retained []string
	}{
		{name: "disabled"},
		{name: "dns", features: configflows.Features{EnableDNSTracking: true}, cached: []string{ebpf.FlowsBpfMapAggregatedFlowsDns}, retained: []string{ebpf.FlowsBpfMapDnsFlows}},
		{name: "network events", features: configflows.Features{EnableNetworkEventsMonitoring: true}, cached: []string{ebpf.FlowsBpfMapAggregatedFlowsNetworkEvents}},
		{name: "drops", features: configflows.Features{EnablePktDrops: true}, cached: []string{ebpf.FlowsBpfMapAggregatedFlowsPktDrop}},
		{name: "translation", features: configflows.Features{EnablePktTranslationTracking: true}, cached: []string{ebpf.FlowsBpfMapAggregatedFlowsXlat}},
		{name: "rtt only", features: configflows.Features{EnableRTT: true}, cached: []string{ebpf.FlowsBpfMapAdditionalFlowMetrics}},
		{name: "ipsec only", features: configflows.Features{EnableIPsecTracking: true}, cached: []string{ebpf.FlowsBpfMapAdditionalFlowMetrics}, retained: []string{ebpf.FlowsBpfMapIpsecIngressMap, ebpf.FlowsBpfMapIpsecEgressMap}},
		{name: "rtt and ipsec", features: configflows.Features{EnableRTT: true, EnableIPsecTracking: true}, cached: []string{ebpf.FlowsBpfMapAdditionalFlowMetrics}, retained: []string{ebpf.FlowsBpfMapIpsecIngressMap, ebpf.FlowsBpfMapIpsecEgressMap}},
		{name: "filter", filter: true, retained: []string{ebpf.FlowsBpfMapFilterMap, ebpf.FlowsBpfMapPeerFilterMap}},
		{name: "fallback", features: configflows.Features{EnableFlowsRingbufFallback: true}, retained: []string{ebpf.FlowsBpfMapDirectFlows}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ebpf.LoadFlowsBpf()
			require.NoError(t, err)
			expected := spec.Copy()
			for _, name := range []string{
				ebpf.FlowsBpfMapAggregatedFlowsDns, ebpf.FlowsBpfMapAggregatedFlowsNetworkEvents,
				ebpf.FlowsBpfMapAggregatedFlowsPktDrop, ebpf.FlowsBpfMapAggregatedFlowsXlat,
				ebpf.FlowsBpfMapAdditionalFlowMetrics, ebpf.FlowsBpfMapDnsFlows,
				ebpf.FlowsBpfMapFilterMap, ebpf.FlowsBpfMapPeerFilterMap,
				ebpf.FlowsBpfMapIpsecIngressMap, ebpf.FlowsBpfMapIpsecEgressMap,
				ebpf.FlowsBpfMapQuicFlows,
			} {
				expected.Maps[name].MaxEntries = 1
			}
			expected.Maps[ebpf.FlowsBpfMapDirectFlows].MaxEntries = uint32(os.Getpagesize())
			expected.Maps[ebpf.FlowsBpfMapAggregatedFlows].MaxEntries = 5000
			for _, name := range tc.cached {
				expected.Maps[name].MaxEntries = 5000
			}
			for _, name := range tc.retained {
				expected.Maps[name].MaxEntries = spec.Maps[name].MaxEntries
			}
			cfg := &tracer.FetcherConfig{Agent: config.Agent{
				Common: config.Common{CacheMaxFlows: 5000},
				Flows:  tc.features,
			}}
			var filter *attach.Filter
			if tc.filter {
				filter = attach.NewFilter([]*attach.FilterConfig{{Action: "Accept"}})
			}
			configureFlowMaps(spec, cfg, filter)
			// Check capacities, unrelated maps, and the ABI/flags required by the BPF object.
			for name, before := range expected.Maps {
				after := spec.Maps[name]
				assert.Equal(t, before.MaxEntries, after.MaxEntries, name)
				assert.Equal(t, before.KeySize, after.KeySize, name)
				assert.Equal(t, before.ValueSize, after.ValueSize, name)
				assert.Equal(t, before.Type, after.Type, name)
				assert.Equal(t, before.Flags, after.Flags, name)
				assert.Equal(t, before.Pinning, after.Pinning, name)
			}
		})
	}
}
