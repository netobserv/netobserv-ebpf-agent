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
	const srcID, dstID = uint32(1), uint32(2)

	espID := ebpf.BpfFlowId{
		SrcId:             srcID,
		DstId:             dstID,
		TransportProtocol: syscall.IPPROTO_ESP,
	}
	// Geneve/UDP orphan as produced before wire-id normalization
	orphanID := ebpf.BpfFlowId{
		SrcId:             srcID,
		DstId:             dstID,
		SrcPort:           12345,
		DstPort:           6081,
		TransportProtocol: syscall.IPPROTO_UDP,
	}

	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{
		espID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{
				Packets: 10,
				Bytes:   1500,
			},
		},
		orphanID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
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
	const srcID, dstID = uint32(3), uint32(4)

	nattID := ebpf.BpfFlowId{
		SrcId:             srcID,
		DstId:             dstID,
		SrcPort:           udpPortNATT,
		DstPort:           udpPortNATT,
		TransportProtocol: syscall.IPPROTO_UDP,
	}
	orphanID := ebpf.BpfFlowId{
		SrcId:             srcID,
		DstId:             dstID,
		TransportProtocol: syscall.IPPROTO_ESP,
	}

	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{
		nattID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 3, Bytes: 400},
		},
		orphanID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
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
	const srcID, dstID = uint32(5), uint32(6)

	espID := ebpf.BpfFlowId{
		SrcId:             dstID,
		DstId:             srcID,
		TransportProtocol: syscall.IPPROTO_ESP,
	}
	orphanID := ebpf.BpfFlowId{
		SrcId:             srcID,
		DstId:             dstID,
		SrcPort:           9999,
		DstPort:           6081,
		TransportProtocol: syscall.IPPROTO_UDP,
	}

	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{
		espID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 1, Bytes: 100},
		},
		orphanID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				IpsecEncrypted: true,
			},
		},
	}

	mergeIPsecOrphans(flows)

	require.Len(t, flows, 1)
	assert.True(t, flows[espID].AdditionalMetrics.IpsecEncrypted)
}

func TestMergeIPsecOrphansPicksDeterministicTarget(t *testing.T) {
	const srcID, dstID = uint32(7), uint32(8)

	espID := ebpf.BpfFlowId{SrcId: srcID, DstId: dstID, TransportProtocol: syscall.IPPROTO_ESP}
	nattID := ebpf.BpfFlowId{
		SrcId: srcID, DstId: dstID, SrcPort: udpPortNATT, DstPort: udpPortNATT, TransportProtocol: syscall.IPPROTO_UDP,
	}
	orphanID := ebpf.BpfFlowId{
		SrcId: srcID, DstId: dstID, SrcPort: 1, DstPort: 6081, TransportProtocol: syscall.IPPROTO_UDP,
	}

	// After cmpBpfFlowID sort, ESP precedes UDP/4500 (SrcPort 0 < 4500).
	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{
		espID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 5, Bytes: 500},
		},
		nattID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 7, Bytes: 700},
		},
		orphanID: {
			BpfFlowMetrics:    &ebpf.BpfFlowMetrics{},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{IpsecEncrypted: true},
		},
	}

	mergeIPsecOrphans(flows)

	require.Len(t, flows, 2)
	require.NotNil(t, flows[espID].AdditionalMetrics)
	assert.True(t, flows[espID].AdditionalMetrics.IpsecEncrypted)
	assert.Nil(t, flows[nattID].AdditionalMetrics)
}

func TestMergeIPsecOrphansKeepsPartialWhenNoSibling(t *testing.T) {
	orphanID := ebpf.BpfFlowId{
		SrcPort:           1,
		DstPort:           6081,
		TransportProtocol: syscall.IPPROTO_UDP,
	}
	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{
		orphanID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
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
		BpfFlowMetrics:    &ebpf.BpfFlowMetrics{Packets: 1},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{IpsecEncrypted: true},
	}))
	assert.True(t, isIPsecOrphan(model.BpfFlowContent{
		BpfFlowMetrics:    &ebpf.BpfFlowMetrics{},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{IpsecEncrypted: true},
	}))
	assert.True(t, isIPsecOrphan(model.BpfFlowContent{
		BpfFlowMetrics:    &ebpf.BpfFlowMetrics{},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{IpsecEncryptedRet: 2},
	}))
}
