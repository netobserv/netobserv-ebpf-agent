package exporter

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONConversion(t *testing.T) {
	wc := writerCapturer{}
	kj := KafkaJSON{Writer: &wc}
	input := make(chan []*flow.Record, 10)
	record := flow.Record{}
	record.EthProtocol = 3
	record.Direction = 1
	record.SrcMac = [...]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	record.DstMac = [...]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	record.SrcAddr = *(*flow.IPAddr)(net.ParseIP("192.1.2.3")[0:16])
	record.DstAddr = *(*flow.IPAddr)(net.ParseIP("aabb:ccdd:eeff::2233")[0:16])
	record.SrcPort = 4321
	record.DstPort = 1234
	record.Protocol = 210
	record.TimeFlowStart = time.Now().Add(-5 * time.Second)
	record.TimeFlowEnd = time.Now()
	record.Bytes = 789
	record.Packets = 987
	record.Interface = "veth0"

	input <- []*flow.Record{&record}
	close(input)
	kj.ExportFlows(input)

	require.Len(t, wc.messages, 1)
	var msg map[string]interface{}
	require.NoError(t, json.Unmarshal(wc.messages[0].Value, &msg))
	assert.EqualValues(t, 3, msg["Etype"])
	assert.EqualValues(t, 1, msg["Direction"])
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", msg["SrcMac"])
	assert.Equal(t, "11:22:33:44:55:66", msg["DstMac"])
	assert.Equal(t, "192.1.2.3", msg["SrcAddr"])
	assert.Equal(t, "aabb:ccdd:eeff::2233", msg["DstAddr"])
	assert.EqualValues(t, 4321, msg["SrcPort"])
	assert.EqualValues(t, 1234, msg["DstPort"])
	assert.EqualValues(t, 210, msg["Proto"])
	assert.EqualValues(t, record.TimeFlowStart.Unix(), msg["TimeFlowStart"])
	assert.EqualValues(t, record.TimeFlowEnd.Unix(), msg["TimeFlowEnd"])
	assert.EqualValues(t, record.TimeFlowStart.UnixMilli(), msg["TimeFlowStartMs"])
	assert.EqualValues(t, record.TimeFlowEnd.UnixMilli(), msg["TimeFlowEndMs"])
	assert.EqualValues(t, 789, msg["Bytes"])
	assert.EqualValues(t, 987, msg["Packets"])
	assert.Equal(t, "veth0", msg["Interface"])
}

type writerCapturer struct {
	messages []kafkago.Message
}

func (w *writerCapturer) WriteMessages(_ context.Context, msgs ...kafkago.Message) error {
	w.messages = append(w.messages, msgs...)
	return nil
}
