package flow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/sirupsen/logrus"
)

var perflog = logrus.WithField("component", "flow.PerfBufTracer")

// PerfBufTracer receives flows via perfbuffer
type PerfBufTracer struct {
	perfBuffer perfBufReader
	perfStats  perfStats
}

type perfBufReader interface {
	ReadPerfBuf() (perf.Record, error)
}

func NewPerfBufTracer(reader perfBufReader, logTimeout time.Duration) *PerfBufTracer {
	return &PerfBufTracer{
		perfBuffer: reader,
		perfStats:  perfStats{loggingTimeout: logTimeout},
	}
}

// perfStats supports atomic logging of perfBuffer metrics
type perfStats struct {
	loggingTimeout time.Duration
	isForwarding   int32
	forwardedFlows int32
}

func (m *PerfBufTracer) TraceLoop(ctx context.Context) node.StartFunc[*ebpf.BpfSockEventT] {
	return func(out chan<- *ebpf.BpfSockEventT) {
		debugging := logrus.IsLevelEnabled(logrus.DebugLevel)
		for {
			select {
			case <-ctx.Done():
				perflog.Debug("exiting trace loop due to context cancellation")
				return
			default:
				if err := m.listenAndForwardPerfBuffer(debugging, out); err != nil {
					if errors.Is(err, perf.ErrClosed) {
						perflog.Debug("Received signal, exiting..")
						return
					}
					perflog.WithError(err).Warn("ignoring flow event")
					continue
				}
			}
		}
	}
}

func (m *PerfBufTracer) listenAndForwardPerfBuffer(debugging bool, forwardCh chan<- *ebpf.BpfSockEventT) error {
	perflog.Debug("check perfBuffer event")
	event, err := m.perfBuffer.ReadPerfBuf()
	if err != nil {
		return fmt.Errorf("reading from perf buffer: %w", err)
	}
	// Parses the perfbuf event entry into an Event structure.
	readFlow, err := ReadFromPerf(bytes.NewBuffer(event.RawSample))
	if err != nil {
		return fmt.Errorf("parsing data received from the ring buffer: %w", err)
	}
	if debugging {
		m.perfStats.logPerfBuffer()
	}
	forwardCh <- readFlow

	return nil
}

// logPerfBuffer avoids flooding logs on long series of evicted flows by grouping how
// many flows are forwarded
func (m *perfStats) logPerfBuffer() {
	atomic.AddInt32(&m.forwardedFlows, 1)
	if atomic.CompareAndSwapInt32(&m.isForwarding, 0, 1) {
		go func() {
			time.Sleep(m.loggingTimeout)
			l := rtlog.WithFields(logrus.Fields{
				"flows": atomic.LoadInt32(&m.forwardedFlows),
			})
			l.Debug("received flows via perfbuffer")
			atomic.StoreInt32(&m.forwardedFlows, 0)
			atomic.StoreInt32(&m.isForwarding, 0)
		}()
	}
}
