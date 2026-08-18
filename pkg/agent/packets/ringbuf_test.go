package packets

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/gavv/monotime"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPacketReader struct {
	records []ringbuf.Record
	err     error
	idx     int
}

func (m *mockPacketReader) ReadPerf() (ringbuf.Record, error) {
	if m.err != nil {
		return ringbuf.Record{}, m.err
	}
	if m.idx >= len(m.records) {
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	rec := m.records[m.idx]
	m.idx++
	return rec, nil
}

func encodePacketSample(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, uint32(1))) // ifindex
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, uint32(len(payload))))
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, uint64(monotime.Now())))
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, payload))
	return buf.Bytes()
}

func TestRingbufTracerForwardsRecord(t *testing.T) {
	payload := []byte{0xde, 0xad}
	reader := &mockPacketReader{records: []ringbuf.Record{{RawSample: encodePacketSample(t, payload)}}}
	tracer := NewRingbufTracer(reader, time.Second)

	out := make(chan *model.PacketRecord, 1)
	start := tracer.TraceLoop(context.Background())
	go start(out)

	select {
	case rec := <-out:
		assert.Equal(t, payload, rec.Stream)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet record")
	}
}

func TestRingbufTracerListenAndForwardError(t *testing.T) {
	reader := &mockPacketReader{err: ringbuf.ErrClosed}
	tracer := NewRingbufTracer(reader, time.Second)

	out := make(chan *model.PacketRecord)
	err := tracer.listenAndForward(out)
	require.Error(t, err)
	assert.ErrorIs(t, err, ringbuf.ErrClosed)
}
