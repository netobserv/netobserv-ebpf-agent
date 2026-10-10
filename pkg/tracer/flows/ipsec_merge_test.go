package flows

import (
	"syscall"
	"testing"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeIPsecOrphansOntoESP(t *testing.T) {
	src := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 9, 56}
	dst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 62, 177}

	espID := ebpf.FlowsBpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		TransportProtocol: syscall.IPPROTO_ESP,
	}
	// Geneve/UDP orphan as produced before wire-id normalization
	orphanID := ebpf.FlowsBpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		SrcPort:           12345,
		DstPort:           6081,
		TransportProtocol: syscall.IPPROTO_UDP,
	}

	flows := map[ebpf.FlowsBpfFlowId]model.BpfFlowContent{
		espID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
				Packets: 10,
				Bytes:   1500,
			},
		},
		orphanID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{},
			AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
				IpsecEncrypted: true,
			},
		},
	}

	mergeIPsecOrphans(flows)

	require.Len(t, flows, 1)
	merged, ok := flows[espID]
	require.True(t, ok)
	assert.EqualValues(t, 10, merged.Packets)
	assert.EqualValues(t, 1500, merged.Bytes)
	require.NotNil(t, merged.AdditionalMetrics)
	assert.True(t, merged.AdditionalMetrics.IpsecEncrypted)
	_, orphanLeft := flows[orphanID]
	assert.False(t, orphanLeft)
}

func TestMergeIPsecOrphansOntoNATT(t *testing.T) {
	src := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 1, 1}
	dst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 1, 2}

	nattID := ebpf.FlowsBpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		SrcPort:           udpPortNATT,
		DstPort:           udpPortNATT,
		TransportProtocol: syscall.IPPROTO_UDP,
	}
	orphanID := ebpf.FlowsBpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		TransportProtocol: syscall.IPPROTO_ESP,
	}

	flows := map[ebpf.FlowsBpfFlowId]model.BpfFlowContent{
		nattID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{Packets: 3, Bytes: 400},
		},
		orphanID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{},
			AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
				IpsecEncrypted:    true,
				IpsecEncryptedRet: 0,
			},
		},
	}

	mergeIPsecOrphans(flows)

	require.Len(t, flows, 1)
	merged := flows[nattID]
	assert.EqualValues(t, 3, merged.Packets)
	require.NotNil(t, merged.AdditionalMetrics)
	assert.True(t, merged.AdditionalMetrics.IpsecEncrypted)
}

func TestMergeIPsecOrphansSwappedDirection(t *testing.T) {
	src := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 2, 1}
	dst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 2, 2}

	espID := ebpf.FlowsBpfFlowId{
		SrcIp:             dst,
		DstIp:             src,
		TransportProtocol: syscall.IPPROTO_ESP,
	}
	orphanID := ebpf.FlowsBpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		SrcPort:           9999,
		DstPort:           6081,
		TransportProtocol: syscall.IPPROTO_UDP,
	}

	flows := map[ebpf.FlowsBpfFlowId]model.BpfFlowContent{
		espID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{Packets: 1, Bytes: 100},
		},
		orphanID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{},
			AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
				IpsecEncrypted: true,
			},
		},
	}

	mergeIPsecOrphans(flows)

	require.Len(t, flows, 1)
	assert.True(t, flows[espID].AdditionalMetrics.IpsecEncrypted)
}

func TestMergeIPsecOrphansPicksDeterministicTarget(t *testing.T) {
	src := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 3, 1}
	dst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 3, 2}

	espID := ebpf.FlowsBpfFlowId{SrcIp: src, DstIp: dst, TransportProtocol: syscall.IPPROTO_ESP}
	nattID := ebpf.FlowsBpfFlowId{
		SrcIp: src, DstIp: dst, SrcPort: udpPortNATT, DstPort: udpPortNATT, TransportProtocol: syscall.IPPROTO_UDP,
	}
	orphanID := ebpf.FlowsBpfFlowId{
		SrcIp: src, DstIp: dst, SrcPort: 1, DstPort: 6081, TransportProtocol: syscall.IPPROTO_UDP,
	}

	// After cmpBpfFlowID sort, ESP precedes UDP/4500 (SrcPort 0 < 4500).
	flows := map[ebpf.FlowsBpfFlowId]model.BpfFlowContent{
		espID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{Packets: 5, Bytes: 500},
		},
		nattID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{Packets: 7, Bytes: 700},
		},
		orphanID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{},
			AdditionalMetrics:   &ebpf.FlowsBpfAdditionalMetrics{IpsecEncrypted: true},
		},
	}

	mergeIPsecOrphans(flows)

	require.Len(t, flows, 2)
	require.NotNil(t, flows[espID].AdditionalMetrics)
	assert.True(t, flows[espID].AdditionalMetrics.IpsecEncrypted)
	assert.Nil(t, flows[nattID].AdditionalMetrics)
}

func TestMergeIPsecOrphansKeepsPartialWhenNoSibling(t *testing.T) {
	orphanID := ebpf.FlowsBpfFlowId{
		SrcPort:           1,
		DstPort:           6081,
		TransportProtocol: syscall.IPPROTO_UDP,
	}
	flows := map[ebpf.FlowsBpfFlowId]model.BpfFlowContent{
		orphanID: {
			FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{},
			AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
				IpsecEncrypted: true,
			},
		},
	}

	mergeIPsecOrphans(flows)

	require.Len(t, flows, 1)
	assert.True(t, flows[orphanID].AdditionalMetrics.IpsecEncrypted)
}

func TestIsIPsecOrphan(t *testing.T) {
	assert.False(t, isIPsecOrphan(model.BpfFlowContent{}))
	assert.False(t, isIPsecOrphan(model.BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{Packets: 1},
		AdditionalMetrics:   &ebpf.FlowsBpfAdditionalMetrics{IpsecEncrypted: true},
	}))
	assert.True(t, isIPsecOrphan(model.BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{},
		AdditionalMetrics:   &ebpf.FlowsBpfAdditionalMetrics{IpsecEncrypted: true},
	}))
	assert.True(t, isIPsecOrphan(model.BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{},
		AdditionalMetrics:   &ebpf.FlowsBpfAdditionalMetrics{IpsecEncryptedRet: 2},
	}))
}
