package flow

import (
	"time"

	"github.com/sirupsen/logrus"
)

// Accounter accumulates flows metrics in memory and eventually evicts them via an evictor channel.
// It is not safe for concurrent access so if at some point you need to parallelize also the
// accounting process you should either: (1) reimplement the Accounter by using a concurrent map
// implementation and performing the properties operations atomically; or (2) spinup parallel
// accounters that evict the flow records to another accounter that consolidates data from all
// (some kind of map-reduce).
type Accounter struct {
	maxEntries     int
	evictBufferLen int
	evictTimeout   time.Duration
	entries        map[RecordKey]*Record
}

var alog = logrus.WithField("component", "flow/Accounter")

// NewAccounter creates a new Accounter.
// The cache has no limit and it's assumed that eviction is done by the caller.
func NewAccounter(maxEntries, evictBufferLen int, evictTimeout time.Duration) *Accounter {
	return &Accounter{
		maxEntries:     maxEntries,
		evictBufferLen: evictBufferLen,
		evictTimeout:   evictTimeout,
		entries:        make(map[RecordKey]*Record, maxEntries),
	}
}

// Account runs in a new goroutine. It reads all the records from the input channel
// and accumulate their metrics internally. Once the metrics have reached their max size
// or the eviction times out, it evicts all the accumulated flows by the returned channel.
// TODO: this intermediate accumulation is not needed anymore, or at most is only needed
// by the moment, to the ringbuffer edge case.
func (c *Accounter) Account(in <-chan *Record, out chan<- []*Record) {
	evictTick := time.NewTicker(c.evictTimeout)
	defer evictTick.Stop()
	for {
		select {
		case <-evictTick.C:
			evictingEntries := c.entries
			c.entries = make(map[RecordKey]*Record, c.maxEntries)
			go evict(evictingEntries, out)
		case record, ok := <-in:
			if !ok {
				alog.Debug("input channel closed. Evicting entries")
				// if the records channel is closed, we evict the entries in the
				// same goroutine to wait for all the entries to be sent before
				// closing the channel
				evict(c.entries, out)
				alog.Debug("exiting account routine")
				return
			}
			if stored, ok := c.entries[record.RecordKey]; ok {
				stored.Accumulate(&record.RecordMetrics)
			} else {
				if len(c.entries) >= c.maxEntries {
					evictingEntries := c.entries
					c.entries = make(map[RecordKey]*Record, c.maxEntries)
					go evict(evictingEntries, out)
				}
				c.entries[record.RecordKey] = record
			}
		}

	}
}

func evict(entries map[RecordKey]*Record, evictor chan<- []*Record) {
	records := make([]*Record, 0, len(entries))
	for _, record := range entries {
		records = append(records, record)
	}
	evictor <- records
}
