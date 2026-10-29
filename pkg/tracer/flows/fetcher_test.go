package flows

import (
	"fmt"
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

	original := spec.Copy()
	require.NoError(t, configureFlowSpecVariables(spec, cfg, filter))
	for name, m := range original.Maps {
		assert.Equal(t, m.MaxEntries, spec.Maps[name].MaxEntries, name)
	}
}

func TestConfigureQUICMapCapacity(t *testing.T) {
	for _, mode := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			spec, err := ebpf.LoadFlowsBpf()
			require.NoError(t, err)
			original := spec.Maps[ebpf.FlowsBpfMapQuicFlows].MaxEntries
			cfg := &tracer.FetcherConfig{Agent: config.Agent{Flows: configflows.Features{QUICTrackingMode: mode, EnableTLSTracking: true}}}
			configureFlowMaps(spec, cfg, nil)
			require.NoError(t, configureFlowSpecVariables(spec, cfg, nil))
			if mode != 1 && mode != 2 {
				assert.Equal(t, uint32(1), spec.Maps[ebpf.FlowsBpfMapQuicFlows].MaxEntries)
			} else {
				assert.Equal(t, original, spec.Maps[ebpf.FlowsBpfMapQuicFlows].MaxEntries)
			}
			var configured uint8
			require.NoError(t, spec.Variables[ebpf.FlowsBpfVarEnableQuicTracking].Get(&configured))
			expected := uint8(0)
			if mode == 1 || mode == 2 {
				expected = uint8(mode)
			}
			assert.Equal(t, expected, configured)
		})
	}
}
