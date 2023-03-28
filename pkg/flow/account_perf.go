package flow

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

// PerfAccounter eventually perf flow logs via an evictor channel.
type PerfAccounter struct {
	maxEntries   int
	evictTimeout time.Duration
	entries      map[ebpf.BpfSockIdentT]*ebpf.BpfSockEventT
}

var plog = logrus.WithField("component", "flow/PerfAccounter")

// NewPerfAccounter creates a new PerfAccounter.
func NewPerfAccounter(
	maxEntries int, evictTimeout time.Duration,
) *PerfAccounter {
	return &PerfAccounter{
		maxEntries:   maxEntries,
		evictTimeout: evictTimeout,
		entries:      map[ebpf.BpfSockIdentT]*ebpf.BpfSockEventT{},
	}
}

// PerfAccount runs in a new goroutine. It reads all the records from the input channel
// and evicts all the accumulated flows by the returned channel.
func (c *PerfAccounter) PerfAccount(in <-chan *ebpf.BpfSockEventT, out chan<- []*ebpf.BpfSockEventT) {
	evictTick := time.NewTicker(c.evictTimeout)
	defer evictTick.Stop()
	for {
		select {
		case <-evictTick.C:
			if len(c.entries) == 0 {
				break
			}
			evictingEntries := c.entries
			c.entries = map[ebpf.BpfSockIdentT]*ebpf.BpfSockEventT{}
			logrus.WithField("flows", len(evictingEntries)).
				Debug("evicting flows from userspace perfaccounter on timeout")
			c.evict(evictingEntries, out)
		case _, ok := <-in:
			if !ok {
				alog.Debug("input channel closed. Evicting entries")
				// if the records channel is closed, we evict the entries in the
				// same goroutine to wait for all the entries to be sent before
				// closing the channel
				c.evict(c.entries, out)
				alog.Debug("exiting account routine")
				return
			}
		}
	}
}

func (c *PerfAccounter) evict(entries map[ebpf.BpfSockIdentT]*ebpf.BpfSockEventT, evictor chan<- []*ebpf.BpfSockEventT) {
	records := make([]*ebpf.BpfSockEventT, 0, len(entries))
	for _, event := range entries {
		records = append(records, event)
	}
	plog.WithField("numEntries", len(records)).Debug("records evicted from userspace accounter")
	evictor <- records
}
