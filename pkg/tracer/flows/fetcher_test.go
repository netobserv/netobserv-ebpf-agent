package flows

import (
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureFlowSpecVariables(t *testing.T) {
	spec, err := ebpf.LoadFlowsBpf()
	require.NoError(t, err)

	cfg := &tracer.FetcherConfig{
		Agent: config.Agent{
			Common: config.Common{
				Sampling:         25,
				DNSTrackingPorts: []uint16{5353},
			},
			Flows: configflows.Features{
				EnableDNSTracking: true,
				EnableRTT:         true,
				QUICTrackingMode:  2,
			},
		},
		Debug: true,
	}
	filter := attach.NewFilter([]*attach.FilterConfig{{
		Action:    "Accept",
		Direction: "Ingress",
		Protocol:  "TCP",
		Sample:    10,
	}})

	require.NoError(t, configureFlowSpecVariables(spec, cfg, filter))
}

func TestConfigureFlowSpecVariablesNoFilterShrinksMaps(t *testing.T) {
	spec, err := ebpf.LoadFlowsBpf()
	require.NoError(t, err)

	cfg := &tracer.FetcherConfig{Agent: config.Agent{}}
	require.NoError(t, configureFlowSpecVariables(spec, cfg, nil))
	assert.Equal(t, uint32(1), spec.Maps[ebpf.FlowsBpfMapFilterMap].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps[ebpf.FlowsBpfMapPeerFilterMap].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps[ebpf.FlowsBpfMapIpsecIngressMap].MaxEntries)
}

func TestSizeMapForFeature(t *testing.T) {
	spec, err := ebpf.LoadFlowsBpf()
	require.NoError(t, err)

	sizeMapForFeature(spec, ebpf.FlowsBpfMapAggregatedFlowsDns, true, 5000)
	assert.Equal(t, uint32(5000), spec.Maps[ebpf.FlowsBpfMapAggregatedFlowsDns].MaxEntries)

	sizeMapForFeature(spec, ebpf.FlowsBpfMapAggregatedFlowsDns, false, 5000)
	assert.Equal(t, uint32(1), spec.Maps[ebpf.FlowsBpfMapAggregatedFlowsDns].MaxEntries)
}
