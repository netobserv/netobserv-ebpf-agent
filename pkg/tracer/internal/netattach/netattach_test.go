package netattach

import (
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

func TestTCXAnchor(t *testing.T) {
	assert.Equal(t, link.Head(), TCXAnchor(TCXAnchorHead))
	assert.Equal(t, link.Tail(), TCXAnchor(TCXAnchorTail))
	assert.Nil(t, TCXAnchor(TCXAnchorNone))
	assert.Nil(t, TCXAnchor("unknown"))
}

func TestSetVariableFlowSpec(t *testing.T) {
	spec, err := flows.LoadBpf()
	require.NoError(t, err)

	require.NoError(t, SetVariable(spec, flows.BpfVarSampling, uint32(50)))
}

func TestSetVariablePacketSpec(t *testing.T) {
	spec, err := packets.LoadPackets()
	require.NoError(t, err)

	require.NoError(t, SetVariable(spec, packets.PacketsVarSampling, uint32(10)))
}

func TestWithNetNSNone(t *testing.T) {
	called := false
	err := WithNetNS(netns.None(), func() error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
}
