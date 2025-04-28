package flow

import (
	"strconv"
	"sync"
	"testing"
	"time"

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
			// fmt.Printf("in: %s\n", i[0].Interfaces[0].Interface)
			initOut <- i
		}
	})
	limiter := node.AsMiddle((NewCapacityLimiter(metrics.NewMetrics(&metrics.Settings{}))).Limit)
	term := node.AsTerminal(func(termIn <-chan []*model.Record) {
		// Let records accumulate in the channel, and release only when the flow stops growing
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			prev := -1
			for {
				n := len(termIn)
				if n == prev {
					// No new record
					return
				}
				prev = n
				time.Sleep(50 * time.Millisecond)
			}
		}()
		wg.Wait()

		// Start output
		for i := range termIn {
			// fmt.Printf("out: %s\n", i[0].Interfaces[0].Interface)
			outCh <- i
		}
	}, node.ChannelBufferLen(limiterLen))

	init.SendsTo(limiter)
	limiter.SendsTo(term)

	init.Start()

	return inCh, outCh
}
