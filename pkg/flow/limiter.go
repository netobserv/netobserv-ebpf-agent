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
// by the exporter queue and active exporter call. It applies backpressure when
// the byte budget is exhausted and drops only batches that cannot fit by
// themselves or when the exporter queue is full.
type CapacityLimiter struct {
	droppedFlows    int
	metrics         *metrics.Metrics
	maxBytes        uint64
	mu              sync.Mutex
	budgetAvailable *sync.Cond
	inFlight        uint64
	inFlightBatches uint64
}

func NewCapacityLimiter(m *metrics.Metrics, maxBytes uint64) *CapacityLimiter {
	if maxBytes == 0 {
		// Directly constructed test or embedding configs may not have passed
		// through envDefault processing.
		maxBytes = 64 << 20
	}
	limiter := &CapacityLimiter{metrics: m, maxBytes: maxBytes}
	limiter.budgetAvailable = sync.NewCond(&limiter.mu)
	return limiter
}

func (c *CapacityLimiter) Limit(in <-chan []*model.Record, out chan<- *model.FlowBatch) {
	go c.logDroppedFlows()
	for records := range in {
		size := model.EstimateFlowBatchBytes(records)
		parts := []model.FlowBatchPart{{Records: records, EstimatedBytes: size}}
		if size > c.maxBytes {
			// Keep several chunks admissible at once so a large map flush can
			// progress through the exporter without either retaining the whole
			// flush or dropping it as one oversized batch.
			chunkBudget := c.maxBytes / 8
			if chunkBudget == 0 {
				chunkBudget = c.maxBytes
			}
			parts = model.SplitFlowBatchRecords(records, chunkBudget)
		}
		for _, part := range parts {
			if !c.reserve(part.EstimatedBytes) {
				c.drop(part.Records, "byte_budget")
				continue
			}
			batch := model.NewFlowBatch(part.Records, part.EstimatedBytes, func() { c.release(part.EstimatedBytes) })
			select {
			case out <- batch:
			default:
				batch.Release()
				c.drop(part.Records, "exporter_queue_full")
			}
		}
	}
}

func (c *CapacityLimiter) reserve(size uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if size > c.maxBytes {
		return false
	}
	for c.inFlight > c.maxBytes-size {
		c.budgetAvailable.Wait()
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
	c.budgetAvailable.Broadcast()
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
