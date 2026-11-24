package flow

import (
	"sync"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/sirupsen/logrus"
)

const initialLogPeriod = time.Minute
const maxLogPeriod = time.Hour

var cllog = logrus.WithField("component", "capacity.Limiter")

// CapacityLimiter forwards flow batches while bounding estimated bytes retained
// by the exporter queue and active exporter call. It never waits for the
// exporter: a batch that does not fit the byte budget or queue is dropped.
type CapacityLimiter struct {
	droppedFlows    int
	metrics         *metrics.Metrics
	maxBytes        uint64
	mu              sync.Mutex
	inFlight        uint64
	inFlightBatches uint64
}

func NewCapacityLimiter(m *metrics.Metrics, maxBytes uint64) *CapacityLimiter {
	if maxBytes == 0 {
		// Directly constructed test or embedding configs may not have passed
		// through envDefault processing.
		maxBytes = 64 << 20
	}
	return &CapacityLimiter{metrics: m, maxBytes: maxBytes}
}

func (c *CapacityLimiter) Limit(in <-chan []*model.Record, out chan<- *model.FlowBatch) {
	go c.logDroppedFlows()
	for records := range in {
		size := model.EstimateFlowBatchBytes(records)
		if !c.tryReserve(size) {
			c.drop(records, "byte_budget")
			continue
		}
		batch := model.NewFlowBatch(records, size, func() { c.release(size) })
		select {
		case out <- batch:
		default:
			batch.Release()
			c.drop(records, "exporter_queue_full")
		}
	}
}

func (c *CapacityLimiter) tryReserve(size uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if size > c.maxBytes || c.inFlight > c.maxBytes-size {
		return false
	}
	c.inFlight += size
	c.inFlightBatches++
	c.metrics.FlowBatchInFlightBytes.Set(float64(c.inFlight))
	c.metrics.FlowBatchInFlightBatches.Set(float64(c.inFlightBatches))
	return true
}

func (c *CapacityLimiter) release(size uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if size > c.inFlight || c.inFlightBatches == 0 {
		cllog.Errorf("flow batch budget accounting underflow: releasing %d bytes from %d bytes / %d batches", size, c.inFlight, c.inFlightBatches)
		c.inFlight = 0
		c.inFlightBatches = 0
	} else {
		c.inFlight -= size
		c.inFlightBatches--
	}
	c.metrics.FlowBatchInFlightBytes.Set(float64(c.inFlight))
	c.metrics.FlowBatchInFlightBatches.Set(float64(c.inFlightBatches))
}

func (c *CapacityLimiter) drop(records []*model.Record, reason string) {
	c.metrics.DroppedFlowBatches.WithLabelValues(reason).Inc()
	c.metrics.DroppedFlowsCounter.WithSourceAndReason("limiter", reason).Add(float64(len(records)))
	c.droppedFlows += len(records)
}

func (c *CapacityLimiter) logDroppedFlows() {
	logPeriod := initialLogPeriod
	debugging := logrus.IsLevelEnabled(logrus.DebugLevel)
	for {
		time.Sleep(logPeriod)

		// a race condition might happen in this counter but it's not important as it's just for
		// logging purposes
		df := c.droppedFlows
		if df > 0 {
			c.droppedFlows = 0
			cllog.Warnf("%d flows were dropped during the last %s because an in-flight flow batch "+
				"exceeded the memory budget or the exporter queue was full",
				df, logPeriod)

			// if not debug logs, backoff to avoid flooding the log with warning messages
			if !debugging && logPeriod < maxLogPeriod {
				logPeriod *= 2
				if logPeriod > maxLogPeriod {
					logPeriod = maxLogPeriod
				}
			}
		} else {
			logPeriod = initialLogPeriod
		}
	}
}
