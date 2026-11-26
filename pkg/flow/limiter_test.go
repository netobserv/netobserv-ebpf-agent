package flow

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const limiterLen = 50

func TestCapacityLimiter_NoDrop(t *testing.T) {
	// GIVEN a limiter-enabled pipeline
	pipeIn, pipeOut := capacityLimiterPipe()

	// WHEN it buffers less elements than its maximum capacity
	for i := 0; i < limiterLen-1; i++ {
		pipeIn <- []*model.Record{{Interfaces: []model.IntfDirUdn{model.NewIntfDirUdn(strconv.Itoa(i), 0, nil)}}}
	}

	// THEN it is able to retrieve all the buffered elements
	for i := 0; i < limiterLen-1; i++ {
		elem := <-pipeOut
		require.Len(t, elem, 1)
		assert.Equal(t, strconv.Itoa(i), elem[0].Interfaces[0].Interface)
	}

	// AND not a single extra element
	select {
	case elem := <-pipeOut:
		assert.Failf(t, "unexpected element", "%#v", elem)
	default:
		// ok!
	}
}

func TestCapacityLimiter_Drop(t *testing.T) {
	// GIVEN a limiter-enabled pipeline
	pipeIn, pipeOut := capacityLimiterPipe()

	// WHEN it receives more elements than its maximum capacity
	// (it's not blocking)
	for i := 0; i < limiterLen+2; i++ {
		pipeIn <- []*model.Record{{Interfaces: []model.IntfDirUdn{model.NewIntfDirUdn(strconv.Itoa(i), 0, nil)}}}
	}

	// THEN it is only able to retrieve all the nth first buffered elements
	for i := 0; i < limiterLen; i++ {
		elem := <-pipeOut
		require.Len(t, elem, 1)
		assert.Equal(t, strconv.Itoa(i), elem[0].Interfaces[0].Interface)
	}

	// BUT not a single extra element
	select {
	case elem := <-pipeOut:
		var first *model.Record
		if len(elem) > 0 {
			first = elem[0]
		}
		assert.Failf(t, "unexpected element", "size: %d, first: %#v", len(elem), first)
	default:
		// ok!
	}
}

func capacityLimiterPipe() (chan<- []*model.Record, <-chan []*model.Record) {
	inCh, outCh := make(chan []*model.Record), make(chan []*model.Record)

	init := node.AsInit(func(initOut chan<- []*model.Record) {
		for i := range inCh {
			initOut <- i
		}
	})
	limiter := node.AsMiddle((NewCapacityLimiter(metrics.NoOp(), 1<<30)).Limit)
	term := node.AsTerminal(func(termIn <-chan *model.FlowBatch) {
		// Let records accumulate in the channel, and release only when the flow stops growing
		prev := -1
		for {
			n := len(termIn)
			if n == prev {
				// No new record
				break
			}
			prev = n
			time.Sleep(50 * time.Millisecond)
		}

		// Start output
		for batch := range termIn {
			outCh <- batch.Records
			batch.Release()
		}
	}, node.ChannelBufferLen(limiterLen))

	init.SendsTo(limiter)
	limiter.SendsTo(term)

	init.Start()

	return inCh, outCh
}

func TestCapacityLimiter_BoundsVariableSizedBatchesWithSlowExporter(t *testing.T) {
	m := metrics.NoOp()
	small := []*model.Record{{Interfaces: []model.IntfDirUdn{model.NewIntfDirUdn("veth0", 0, nil)}}}
	large := []*model.Record{{Interfaces: []model.IntfDirUdn{model.NewIntfDirUdn(strings.Repeat("x", 2048), 0, nil)}}}
	smallBytes := model.EstimateFlowBatchBytes(small)
	largeBytes := model.EstimateFlowBatchBytes(large)
	budget := 2*smallBytes + largeBytes - 1

	in := make(chan []*model.Record)
	out := make(chan *model.FlowBatch, 3)
	limiter := NewCapacityLimiter(m, budget)
	done := make(chan struct{})
	go func() {
		limiter.Limit(in, out)
		close(done)
	}()
	releaseExporter := make(chan struct{})
	exporterStarted := make(chan struct{})
	exporterDone := make(chan struct{})
	go func() {
		batch := <-out
		close(exporterStarted)
		<-releaseExporter // simulate a slow downstream exporter
		batch.Release()
		for batch := range out {
			batch.Release()
		}
		close(exporterDone)
	}()
	in <- small
	<-exporterStarted
	in <- small
	in <- large
	close(in)

	assert.Equal(t, float64(2*smallBytes), metricFloat(t, m.FlowBatchInFlightBytes))
	assert.Equal(t, float64(2), metricFloat(t, m.FlowBatchInFlightBatches))
	assert.Zero(t, metricFloat(t, m.DroppedFlowBatches.WithLabelValues("byte_budget")))

	// The slow exporter holds one batch while the other remains queued.
	assert.LessOrEqual(t, metricFloat(t, m.FlowBatchInFlightBytes), float64(budget))
	assert.Equal(t, float64(2), metricFloat(t, m.FlowBatchInFlightBatches))
	close(releaseExporter)
	<-done
	close(out)
	<-exporterDone
	assert.Zero(t, metricFloat(t, m.FlowBatchInFlightBytes))
	assert.Zero(t, metricFloat(t, m.FlowBatchInFlightBatches))
	assert.Zero(t, metricFloat(t, m.DroppedFlowBatches.WithLabelValues("byte_budget")))
}

func metricFloat(t *testing.T, metric interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	data := &dto.Metric{}
	require.NoError(t, metric.Write(data))
	if data.Gauge != nil {
		return data.Gauge.GetValue()
	}
	return data.Counter.GetValue()
}
