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
	spec, err := ebpf.LoadBpf()
	require.NoError(t, err)

	cfg := &tracer.FetcherConfig{
		Agent: config.Agent{
			Common: config.Common{
				Sampling:         25,
				DNSTrackingPorts: []uint16{5353},
			},
			Flows: configflows.Features{
				EndpointMapMaxEntries: 1048576,
				EnableDNSTracking:     true,
				EnableRTT:             true,
				QUICTrackingMode:      2,
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
	spec, err := ebpf.LoadBpf()
	require.NoError(t, err)

	cfg := &tracer.FetcherConfig{Agent: config.Agent{Flows: configflows.Features{EndpointMapMaxEntries: 1048576}}}
	require.NoError(t, configureFlowSpecVariables(spec, cfg, nil))
	assert.Equal(t, uint32(1), spec.Maps[ebpf.BpfMapFilterMap].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps[ebpf.BpfMapPeerFilterMap].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps[ebpf.BpfMapIpsecIngressMap].MaxEntries)
}

func TestSizeMapForFeature(t *testing.T) {
	spec, err := ebpf.LoadBpf()
	require.NoError(t, err)

	sizeMapForFeature(spec, ebpf.BpfMapAggregatedFlowsDns, true, 5000)
	assert.Equal(t, uint32(5000), spec.Maps[ebpf.BpfMapAggregatedFlowsDns].MaxEntries)

	sizeMapForFeature(spec, ebpf.BpfMapAggregatedFlowsDns, false, 5000)
	assert.Equal(t, uint32(1), spec.Maps[ebpf.BpfMapAggregatedFlowsDns].MaxEntries)
}

func TestConfigureEndpointCapacity(t *testing.T) {
	for _, capacity := range []uint32{2, 4096, 1048576} {
		spec, err := ebpf.LoadBpf()
		require.NoError(t, err)
		cfg := &tracer.FetcherConfig{Agent: config.Agent{
			Flows: configflows.Features{EndpointMapMaxEntries: capacity},
		}}
		require.NoError(t, configureFlowSpecVariables(spec, cfg, nil))
		assert.Equal(t, capacity, spec.Maps[ebpf.BpfMapEndpointIds].MaxEntries)
		assert.Equal(t, capacity, spec.Maps[ebpf.BpfMapEndpointIps].MaxEntries)
	}
	spec, err := ebpf.LoadBpf()
	require.NoError(t, err)
	require.ErrorContains(t, configureFlowSpecVariables(spec, &tracer.FetcherConfig{}, nil), "ENDPOINT_MAP_MAX_ENTRIES")
}
