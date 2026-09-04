package packets

import (
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferEvictsOnMaxEntries(t *testing.T) {
	in := make(chan *model.PacketRecord, 4)
	out := make(chan []*model.PacketRecord, 1)
	buf := NewBuffer(2, time.Hour)

	go buf.PBuffer(in, out)

	in <- model.NewPacketRecord([]byte{1}, 1, time.Unix(1, 0))
	in <- model.NewPacketRecord([]byte{2}, 1, time.Unix(2, 0))
	in <- model.NewPacketRecord([]byte{3}, 1, time.Unix(3, 0))

	var batch []*model.PacketRecord
	select {
	case batch = <-out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for eviction batch")
	}
	require.Len(t, batch, 2)
	assert.Equal(t, byte(1), batch[0].Stream[0])
	assert.Equal(t, byte(2), batch[1].Stream[0])

	close(in)
}

func TestBufferEvictsOnClose(t *testing.T) {
	in := make(chan *model.PacketRecord, 2)
	out := make(chan []*model.PacketRecord, 1)
	buf := NewBuffer(10, time.Hour)

	go buf.PBuffer(in, out)
	in <- model.NewPacketRecord([]byte{9}, 1, time.Unix(9, 0))
	close(in)

	batch := <-out
	require.Len(t, batch, 1)
	assert.Equal(t, byte(9), batch[0].Stream[0])
}
