package flow

import (
	"strconv"
	"testing"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const limiterLen = 50

func TestCapacityLimiter_NoDrop(t *testing.T) {
	// GIVEN a limiter-enabled pipeline
	pipeIn, pipeOut := capacityLimiterPipe()

	// WHEN it buffers less elements than it's maximum capacity
	for i := 0; i < 33; i++ {
		pipeIn <- []*model.Record{{Interface: strconv.Itoa(i)}}
	}

	// THEN it is able to retrieve all the buffered elements
	for i := 0; i < 33; i++ {
		elem := <-pipeOut
		require.Len(t, elem, 1)
		assert.Equal(t, strconv.Itoa(i), elem[0].Interface)
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
	for i := 0; i < limiterLen*2; i++ {
		pipeIn <- []*model.Record{{Interface: strconv.Itoa(i)}}
	}

	// THEN it is only able to retrieve all the nth first buffered elements
	// (plus the single element that is buffered in the output channel)
	for i := 0; i < limiterLen+1; i++ {
		elem := <-pipeOut
		require.Len(t, elem, 1)
		assert.Equal(t, strconv.Itoa(i), elem[0].Interface)
	}

	// BUT not a single extra element
	select {
	case elem := <-pipeOut:
		assert.Failf(t, "unexpected element", "%#v", elem)
	default:
		// ok!
	}
}

func capacityLimiterPipe() (in chan<- []*model.Record, out <-chan []*model.Record) {
	inCh, outCh := make(chan []*model.Record), make(chan []*model.Record)

	init := node.AsInit(func(initOut chan<- []*model.Record) {
		for i := range inCh {
			initOut <- i
		}
	})
	limiter := node.AsMiddle((NewCapacityLimiter(metrics.NewMetrics(&metrics.Settings{}))).Limit)
	term := node.AsTerminal(func(termIn <-chan []*model.Record) {
		for i := range termIn {
			outCh <- i
		}
	}, node.ChannelBufferLen(limiterLen))

	init.SendsTo(limiter)
	limiter.SendsTo(term)

	init.Start()

	return inCh, outCh
}
