package exporter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// IPAddrFromNetIP returns IPAddr from net.IP
func IPAddrFromNetIP(netIP net.IP) flow.IPAddr {
	var arr [net.IPv6len]uint8
	copy(arr[:], (netIP)[0:net.IPv6len])
	return arr
}

func TestProtoConversion(t *testing.T) {
	wc := writerCapturer{}
	kj := KafkaProto{Writer: &wc}
	input := make(chan []*flow.Record, 11)
	record := flow.Record{}
	record.Id.EthProtocol = 3
	record.Id.Direction = 1
	record.Id.SrcMac = [...]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	record.Id.DstMac = [...]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	record.Id.SrcIp = IPAddrFromNetIP(net.ParseIP("192.1.2.3"))
	record.Id.DstIp = IPAddrFromNetIP(net.ParseIP("127.3.2.1"))
	record.Id.SrcPort = 4321
	record.Id.DstPort = 1234
	record.Id.TransportProtocol = 210
	record.TimeFlowStart = time.Now().Add(-5 * time.Second)
	record.TimeFlowEnd = time.Now()
	record.Metrics.Bytes = 789
	record.Metrics.Packets = 987
	record.Metrics.Flags = uint16(1)
	record.Interface = "veth0"

	input <- []*flow.Record{&record}
	close(input)
	kj.ExportFlows(input)

	require.Len(t, wc.messages, 1)
	var r pbflow.Record
	require.NoError(t, proto.Unmarshal(wc.messages[0].Value, &r))
	assert.EqualValues(t, 3, r.EthProtocol)
	assert.EqualValues(t, 1, r.Direction)
	assert.EqualValues(t, uint64(0xaabbccddeeff), r.DataLink.SrcMac)
	assert.EqualValues(t, uint64(0x112233445566), r.DataLink.DstMac)
	assert.EqualValues(t, uint64(0xC0010203) /* 192.1.2.3 */, r.Network.SrcAddr.GetIpv4())
	assert.EqualValues(t, 0x7F030201 /* 127.3.2.1 */, r.Network.DstAddr.GetIpv4())
	assert.EqualValues(t, 4321, r.Transport.SrcPort)
	assert.EqualValues(t, 1234, r.Transport.DstPort)
	assert.EqualValues(t, 210, r.Transport.Protocol)
	assert.Equal(t, record.TimeFlowStart.UnixMilli(), r.TimeFlowStart.AsTime().UnixMilli())
	assert.Equal(t, record.TimeFlowEnd.UnixMilli(), r.TimeFlowEnd.AsTime().UnixMilli())
	assert.EqualValues(t, 789, r.Bytes)
	assert.EqualValues(t, 987, r.Packets)
	assert.EqualValues(t, uint16(1), r.Flags)
	assert.Equal(t, "veth0", r.Interface)
}

type writerCapturer struct {
	messages []kafkago.Message
}

func (w *writerCapturer) WriteMessages(_ context.Context, msgs ...kafkago.Message) error {
	w.messages = append(w.messages, msgs...)
	return nil
}
