package tracer

import (
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeIPsecOrphansOntoESP(t *testing.T) {
	src := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 9, 56}
	dst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 62, 177}

	espID := ebpf.BpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		TransportProtocol: protoESP,
	}
	// Geneve/UDP orphan as produced before wire-id normalization
	orphanID := ebpf.BpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		SrcPort:           12345,
		DstPort:           6081,
		TransportProtocol: protoUDP,
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
	src := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 1, 1}
	dst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 1, 2}

	nattID := ebpf.BpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		SrcPort:           4500,
		DstPort:           4500,
		TransportProtocol: protoUDP,
	}
	orphanID := ebpf.BpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		TransportProtocol: protoESP,
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
	src := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 2, 1}
	dst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 2, 2}

	espID := ebpf.BpfFlowId{
		SrcIp:             dst,
		DstIp:             src,
		TransportProtocol: protoESP,
	}
	orphanID := ebpf.BpfFlowId{
		SrcIp:             src,
		DstIp:             dst,
		SrcPort:           9999,
		DstPort:           6081,
		TransportProtocol: protoUDP,
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

func TestMergeIPsecOrphansKeepsPartialWhenNoSibling(t *testing.T) {
	orphanID := ebpf.BpfFlowId{
		SrcPort:           1,
		DstPort:           6081,
		TransportProtocol: protoUDP,
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
