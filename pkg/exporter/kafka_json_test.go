package exporter

import (
	"context"
	"encoding/json"
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
	record.Network.SrcAddr = 0xC0010203
	record.Transport.DstPort = 1234
	record.Protocol = 3
	record.Bytes = 789
	record.Packets = 987
	record.TimeFlowStart = time.Now().Add(-5 * time.Second)
	record.TimeFlowEnd = time.Now()

	input <- []*flow.Record{&record}
	close(input)
	kj.ExportFlows(context.Background(), input)

	require.Len(t, wc.messages, 1)
	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(wc.messages[0].Value, &forwarded))
	assert.Equal(t, "192.1.2.3", forwarded["SrcAddr"])
	assert.EqualValues(t, 1234, forwarded["DstPort"])
	assert.EqualValues(t, 3, forwarded["Protocol"])
	assert.EqualValues(t, 789, forwarded["Bytes"])
	assert.EqualValues(t, 987, forwarded["Packets"])
	assert.EqualValues(t, record.TimeFlowStart.Unix(), forwarded["TimeFlowStart"])
	assert.EqualValues(t, record.TimeFlowEnd.Unix(), forwarded["TimeFlowEnd"])
	assert.EqualValues(t, record.TimeFlowStart.UnixMilli(), forwarded["TimeFlowStartMs"])
	assert.EqualValues(t, record.TimeFlowEnd.UnixMilli(), forwarded["TimeFlowEndMs"])
}

type writerCapturer struct {
	messages []kafkago.Message
}

func (w *writerCapturer) WriteMessages(ctx context.Context, msgs ...kafkago.Message) error {
	w.messages = append(w.messages, msgs...)
	return nil
}
