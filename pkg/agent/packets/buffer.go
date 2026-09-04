package packets

import (
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/sirupsen/logrus"
)

var blog = logrus.WithField("component", "packet.Buffer")

// Buffer batches packet records before export.
type Buffer struct {
	maxEntries   int
	evictTimeout time.Duration
	entries      []*model.PacketRecord
}

// NewBuffer creates a packet batching buffer.
func NewBuffer(maxEntries int, evictTimeout time.Duration) *Buffer {
	return &Buffer{
		maxEntries:   maxEntries,
		evictTimeout: evictTimeout,
		entries:      []*model.PacketRecord{},
	}
}

// PBuffer reads packet records from in and forwards batched slices to out.
func (c *Buffer) PBuffer(in <-chan *model.PacketRecord, out chan<- []*model.PacketRecord) {
	evictTick := time.NewTicker(c.evictTimeout)
	defer evictTick.Stop()
	for {
		select {
		case <-evictTick.C:
			if len(c.entries) == 0 {
				break
			}
			evictingEntries := c.entries
			c.entries = []*model.PacketRecord{}
			blog.WithField("packets", len(evictingEntries)).
				Debug("evicting packets from userspace buffer on timeout")
			c.evict(evictingEntries, out)
		case packet, ok := <-in:
			if !ok {
				blog.Debug("input channel closed, evicting entries")
				c.evict(c.entries, out)
				blog.Debug("exiting buffer routine")
				return
			}
			if len(c.entries) >= c.maxEntries {
				evictingEntries := c.entries
				c.entries = []*model.PacketRecord{}
				blog.WithField("packets", len(evictingEntries)).
					Debug("evicting packets from userspace buffer after reaching cache max length")
				c.evict(evictingEntries, out)
			}
			c.entries = append(c.entries, model.NewPacketRecord(packet.Stream, uint32(len(packet.Stream)), packet.Time))
		}
	}
}

func (c *Buffer) evict(entries []*model.PacketRecord, evictor chan<- []*model.PacketRecord) {
	packets := make([]*model.PacketRecord, 0, len(entries))
	for _, payload := range entries {
		packets = append(packets, model.NewPacketRecord(payload.Stream, uint32(len(payload.Stream)), payload.Time))
	}
	blog.WithField("numEntries", len(packets)).Debug("packets evicted from userspace buffer")
	evictor <- packets
}
