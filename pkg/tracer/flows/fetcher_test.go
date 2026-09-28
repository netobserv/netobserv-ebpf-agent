package flows

import (
	"os"
	"strings"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Run with NETOBSERV_PRIVILEGED_TESTS=1 in a privileged container. Minimal BPF
// programs exercise the real load/assign and object conversion paths without
// requiring every supported kernel's tracing hooks on the test host.
func TestKernelSpecificLoadersKeepOpenSSLPrograms(t *testing.T) {
	if os.Getenv("NETOBSERV_PRIVILEGED_TESTS") != "1" {
		t.Skip("requires BPF privileges; set NETOBSERV_PRIVILEGED_TESTS=1")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	for _, tc := range []struct {
		name                    string
		old, rt, events, netkit bool
	}{
		{name: "old-rt", old: true, rt: true},
		{name: "old", old: true},
		{name: "rt", rt: true},
		{name: "no-network-events"},
		{name: "netkit", events: true, netkit: true},
		{name: "default", events: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ebpf.LoadBpf()
			require.NoError(t, err)
			for name := range spec.Programs {
				spec.Programs[name] = &cilium.ProgramSpec{
					Type:         cilium.SocketFilter,
					License:      "GPL",
					Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
				}
			}
			for name := range spec.Maps {
				// Preserve global data maps backing generated variable bindings.
				if strings.HasPrefix(name, ".") {
					continue
				}
				spec.Maps[name] = &cilium.MapSpec{
					Type: cilium.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1,
				}
			}
			objects, err := kernelSpecificLoadAndAssign(tc.old, tc.rt, tc.events, tc.netkit, spec, "")
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, objects.Close()) })
			for name, program := range map[string]*cilium.Program{
				"SSL_write":                   objects.ProbeEntrySSL_write,
				"SSL_read entry":              objects.ProbeEntrySSL_read,
				"SSL_read return":             objects.ProbeRetSSL_read,
				"SSL_set_fd entry":            objects.ProbeEntrySSL_setFd,
				"SSL_set_fd return":           objects.ProbeRetSSL_setFd,
				"SSL_free / BIO invalidation": objects.ProbeEntrySSL_free,
			} {
				if assert.NotNil(t, program, name) {
					_, err := program.Info()
					assert.NoError(t, err, name)
				}
			}
		})
	}
}

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
