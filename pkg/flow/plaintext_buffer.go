package flow

import (
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/sirupsen/logrus"
)

var plogtext = logrus.WithField("component", "packet/PlaintextBuffer")

// PlaintextBuffer batches plaintext records before export.
type PlaintextBuffer struct {
	maxEntries   int
	evictTimeout time.Duration
	entries      []*model.PlaintextRecord
}

func NewPlaintextBuffer(maxEntries int, evictTimeout time.Duration) *PlaintextBuffer {
	return &PlaintextBuffer{
		maxEntries:   maxEntries,
		evictTimeout: evictTimeout,
		entries:      []*model.PlaintextRecord{},
	}
}

func (c *PlaintextBuffer) PBuffer(in <-chan *model.PlaintextRecord, out chan<- []*model.PlaintextRecord) {
	evictTick := time.NewTicker(c.evictTimeout)
	defer evictTick.Stop()
	for {
		select {
		case <-evictTick.C:
			if len(c.entries) == 0 {
				break
			}
			c.evict(out)
		case rec, ok := <-in:
			if !ok {
				if len(c.entries) > 0 {
					c.evict(out)
				}
				return
			}
			if len(c.entries) >= c.maxEntries {
				c.evict(out)
			}
			c.entries = append(c.entries, rec)
		}
	}
}

func (c *PlaintextBuffer) evict(out chan<- []*model.PlaintextRecord) {
	batch := c.entries
	c.entries = []*model.PlaintextRecord{}
	plogtext.WithField("records", len(batch)).Debug("evicting plaintext records")
	out <- batch
}
