package exporter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func ByteArrayFromNetIP(netIP net.IP) []uint8 {
	var arr [net.IPv6len]uint8
	copy(arr[:], (netIP)[0:net.IPv6len])
	return arr[:]
}

func TestProtoConversion(t *testing.T) {
	wc := writerCapturer{}
	m := metrics.NewMetrics(&metrics.Settings{})

	kj := KafkaProto{Writer: &wc, Metrics: m}
	input := make(chan []*model.Record, 11)
	record := model.Record{
		TimeFlowStart: time.Now().Add(-5 * time.Second),
		TimeFlowEnd:   time.Now(),
		ID: ebpf.BpfFlowId{
			Direction:         1,
			SrcIp:             model.IPAddrFromNetIP(net.ParseIP("192.1.2.3")),
			DstIp:             model.IPAddrFromNetIP(net.ParseIP("127.3.2.1")),
			SrcPort:           4321,
			DstPort:           1234,
			IcmpType:          8,
			TransportProtocol: 210,
		},
		Metrics: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{
				EthProtocol: 3,
				SrcMac:      [...]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				DstMac:      [...]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				Bytes:       789,
				Packets:     987,
				Flags:       uint16(1),
			},
		},
		Interface: "veth0",
	}

	input <- []*model.Record{&record}
	close(input)
	kj.ExportFlows(input)

	require.Len(t, wc.messages, 1)
	var r pbflow.Record
	require.NoError(t, proto.Unmarshal(wc.messages[0].Value, &r))
	assert.EqualValues(t, 3, r.EthProtocol)
	for _, e := range r.DupList {
		assert.EqualValues(t, 1, e.Direction)
		assert.Equal(t, "veth0", e.Interface)
	}
	assert.EqualValues(t, uint64(0xaabbccddeeff), r.DataLink.SrcMac)
	assert.EqualValues(t, uint64(0x112233445566), r.DataLink.DstMac)
	assert.EqualValues(t, uint64(0xC0010203) /* 192.1.2.3 */, r.Network.SrcAddr.GetIpv4())
	assert.EqualValues(t, 0x7F030201 /* 127.3.2.1 */, r.Network.DstAddr.GetIpv4())
	assert.EqualValues(t, 4321, r.Transport.SrcPort)
	assert.EqualValues(t, 1234, r.Transport.DstPort)
	assert.EqualValues(t, 210, r.Transport.Protocol)
	assert.EqualValues(t, 8, r.IcmpType)
	assert.Equal(t, record.TimeFlowStart.UnixMilli(), r.TimeFlowStart.AsTime().UnixMilli())
	assert.Equal(t, record.TimeFlowEnd.UnixMilli(), r.TimeFlowEnd.AsTime().UnixMilli())
	assert.EqualValues(t, 789, r.Bytes)
	assert.EqualValues(t, 987, r.Packets)
	assert.EqualValues(t, uint16(1), r.Flags)
	assert.Equal(t, ByteArrayFromNetIP(net.ParseIP("127.3.2.1")), wc.messages[0].Key[0:16])
	assert.Equal(t, ByteArrayFromNetIP(net.ParseIP("192.1.2.3")), wc.messages[0].Key[16:])
}

func TestIdenticalKeys(t *testing.T) {
	record := model.Record{
		TimeFlowStart: time.Now().Add(-5 * time.Second),
		TimeFlowEnd:   time.Now(),
		ID: ebpf.BpfFlowId{
			Direction:         1,
			SrcIp:             model.IPAddrFromNetIP(net.ParseIP("192.1.2.3")),
			DstIp:             model.IPAddrFromNetIP(net.ParseIP("127.3.2.1")),
			SrcPort:           4321,
			DstPort:           1234,
			IcmpType:          8,
			TransportProtocol: 210,
		},
		Metrics: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{
				EthProtocol: 3,
				SrcMac:      [...]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				DstMac:      [...]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				Bytes:       789,
				Packets:     987,
				Flags:       uint16(1),
			},
		},
		Interface: "veth0",
	}
	key1 := getFlowKey(&record)

	record.ID.SrcIp = model.IPAddrFromNetIP(net.ParseIP("127.3.2.1"))
	record.ID.DstIp = model.IPAddrFromNetIP(net.ParseIP("192.1.2.3"))
	key2 := getFlowKey(&record)

	// Both keys should be identical
	assert.Equal(t, key1, key2)

}

type writerCapturer struct {
	messages []kafkago.Message
}

func (w *writerCapturer) WriteMessages(_ context.Context, msgs ...kafkago.Message) error {
	w.messages = append(w.messages, msgs...)
	return nil
}
