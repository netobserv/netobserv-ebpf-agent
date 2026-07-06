package pbflow

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

func TestFlowToPBMarshalRoundTrip(t *testing.T) {
	var id ebpf.BpfFlowId
	copy(id.SrcIp[:], net.IPv4(10, 1, 2, 3).To16())
	copy(id.DstIp[:], net.IPv4(10, 1, 2, 4).To16())
	id.SrcPort = 45678
	id.DstPort = 443
	id.TransportProtocol = 6

	now := time.Now()
	rec := &model.Record{
		ID: id,
		Metrics: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{
				Bytes:       12345,
				Packets:     42,
				EthProtocol: 0x0800, // IPv4
				Flags:       0x10,
				SrcMac:      [6]uint8{0x02, 0, 0, 0, 0, 0x01},
				DstMac:      [6]uint8{0x02, 0, 0, 0, 0, 0x02},
				Dscp:        7,
			},
		},
		TimeFlowStart: now.Add(-time.Second).Truncate(0),
		TimeFlowEnd:   now.Truncate(0),
		AgentIP:       net.IPv4(10, 0, 0, 1),
		Interfaces: []model.IntfDirUdn{
			{Interface: "eth0", Direction: 1},
			{Interface: "ovn-k8s-mp0", Direction: 0, Udn: "tenant-blue"},
		},
	}

	pb := FlowToPB(rec)

	raw, err := proto.Marshal(pb)
	require.NoError(t, err)
	var got Record
	require.NoError(t, proto.Unmarshal(raw, &got))

	assert.Equal(t, rec.Metrics.Bytes, got.GetBytes())
	assert.Equal(t, uint64(rec.Metrics.Packets), got.GetPackets())
	assert.Equal(t, uint32(rec.ID.DstPort), got.GetTransport().GetDstPort())
	assert.Equal(t, uint32(rec.ID.SrcPort), got.GetTransport().GetSrcPort())
	assert.Equal(t, uint32(rec.Metrics.Dscp), got.GetNetwork().GetDscp())
	assert.Equal(t, pb.GetDataLink().GetSrcMac(), got.GetDataLink().GetSrcMac())
	assert.Equal(t, rec.TimeFlowStart.Unix(), got.GetTimeFlowStart().GetSeconds())
	assert.Equal(t, rec.TimeFlowEnd.Unix(), got.GetTimeFlowEnd().GetSeconds())

	require.Len(t, got.GetDupList(), 2)
	assert.Equal(t, "eth0", got.GetDupList()[0].GetInterface())
	assert.Equal(t, Direction(1), got.GetDupList()[0].GetDirection())
	assert.Equal(t, "ovn-k8s-mp0", got.GetDupList()[1].GetInterface())
	assert.Equal(t, Direction(0), got.GetDupList()[1].GetDirection())
	assert.Equal(t, "tenant-blue", got.GetDupList()[1].GetUdn())

	// RTT remains present on the wire when its value is zero.
	require.NotNil(t, got.GetTimeFlowRtt())
	assert.Equal(t, time.Duration(0), got.GetTimeFlowRtt().AsDuration())

	back := PBToFlow(&got)
	assert.Equal(t, rec.Metrics.Bytes, back.Metrics.Bytes)
	assert.Equal(t, rec.Metrics.Packets, back.Metrics.Packets)
	assert.Equal(t, time.Duration(0), back.TimeFlowRtt)
	assert.Equal(t, rec.Interfaces, back.Interfaces)
}

func TestFlowToPBRttSet(t *testing.T) {
	rec := &model.Record{
		Metrics: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{EthProtocol: 0x0800}, // IPv4
		},
		TimeFlowRtt: 5 * time.Millisecond,
		AgentIP:     net.IPv4(10, 0, 0, 1),
	}
	pb := FlowToPB(rec)
	require.NotNil(t, pb.GetTimeFlowRtt())
	assert.Equal(t, 5*time.Millisecond, pb.GetTimeFlowRtt().AsDuration())
	assert.Equal(t, 5*time.Millisecond, PBToFlow(pb).TimeFlowRtt)
}
