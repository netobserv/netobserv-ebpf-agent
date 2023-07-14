package flow

import (
	"time"

	"github.com/sirupsen/logrus"
)

type PerfBuffer struct {
	maxEntries   int
	evictTimeout time.Duration
	entries      map[uint32][]byte
}

func NewPerfBuffer(
	maxEntries int, evictTimeout time.Duration,
) *PerfBuffer {
	return &PerfBuffer{
		maxEntries:   maxEntries,
		evictTimeout: evictTimeout,
		entries:      map[uint32][]byte{},
	}
}

func (c *PerfBuffer) PBuffer(in <-chan *PacketRecord, out chan<- []*PacketRecord) {
	evictTick := time.NewTicker(c.evictTimeout)
	defer evictTick.Stop()
	ind := 0
	for {
		select {
		case <-evictTick.C:
			if len(c.entries) == 0 {
				break
			}
			evictingEntries := c.entries
			c.entries = map[uint32][]byte{}
			logrus.WithField("packets", len(evictingEntries)).
				Debug("evicting packets from userspace  on timeout")
			c.evict(evictingEntries, out)
		case packet, ok := <-in:
			if !ok {
				plog.Debug("input channel closed. Evicting entries")
				// if the packets channel is closed, we evict the entries in the
				// same goroutine to wait for all the entries to be sent before
				// closing the channel
				c.evict(c.entries, out)
				plog.Debug("exiting perfbuffer routine")
				return
			}
			if len(c.entries) >= c.maxEntries {
				evictingEntries := c.entries
				c.entries = map[uint32][]byte{}
				logrus.WithField("packets", len(evictingEntries)).
					Debug("evicting packets from userspace accounter after reaching cache max length")
				c.evict(evictingEntries, out)
			}
			c.entries[uint32(ind)] = packet.Stream
			ind++

		}
	}
}

func (c *PerfBuffer) evict(entries map[uint32]([]byte), evictor chan<- []*PacketRecord) {
	packets := make([]*PacketRecord, 0, len(entries))
	for _, payload := range entries {
		packets = append(packets, NewPacketRecord(payload, (uint32)(len(payload))))
	}
	alog.WithField("numEntries", len(packets)).Debug("packets evicted from userspace accounter")
	evictor <- packets
}
