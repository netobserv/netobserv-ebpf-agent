package packets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("component", "packet.RingbufTracer")

type ringbufReader interface {
	ReadPerf() (ringbuf.Record, error)
}

// RingbufTracer reads packet capture events from the BPF ringbuf.
type RingbufTracer struct {
	reader ringbufReader
}

func NewRingbufTracer(reader ringbufReader, _ time.Duration) *RingbufTracer {
	return &RingbufTracer{reader: reader}
}

func (m *RingbufTracer) TraceLoop(ctx context.Context) node.StartFunc[*model.PacketRecord] {
	return func(out chan<- *model.PacketRecord) {
		for {
			select {
			case <-ctx.Done():
				log.Debug("exiting trace loop due to context cancellation")
				return
			default:
				if err := m.listenAndForward(out); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						log.Debug("ringbuf closed, exiting")
						return
					}
					log.WithError(err).Warn("ignoring packet event")
				}
			}
		}
	}
}

func (m *RingbufTracer) listenAndForward(forwardCh chan<- *model.PacketRecord) error {
	event, err := m.reader.ReadPerf()
	if err != nil {
		return fmt.Errorf("reading from packet ringbuf: %w", err)
	}
	record, err := model.ReadRawPacket(bytes.NewBuffer(event.RawSample))
	if err != nil {
		return fmt.Errorf("parsing packet ringbuf record: %w", err)
	}
	forwardCh <- record
	return nil
}
