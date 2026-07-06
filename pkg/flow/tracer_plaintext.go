package flow

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/sirupsen/logrus"
	"strconv"
)

var ptlog = logrus.WithField("component", "flow.PlaintextTracer")

// PlaintextProcessor filters and enriches plaintext records before export.
type PlaintextProcessor interface {
	Process(rec *model.PlaintextRecord) bool
}

// PlaintextTracer reads TLS plaintext events from the SSL ringbuf.
type PlaintextTracer struct {
	reader    plaintextReader
	metrics   *metrics.Metrics
	processor PlaintextProcessor
}

type plaintextReader interface {
	ReadSSLRingBuf() (ringbuf.Record, error)
}

func NewPlaintextTracer(reader plaintextReader, m *metrics.Metrics, processor PlaintextProcessor) *PlaintextTracer {
	return &PlaintextTracer{
		reader:    reader,
		metrics:   m,
		processor: processor,
	}
}

func (m *PlaintextTracer) TraceLoop(ctx context.Context) node.StartFunc[*model.PlaintextRecord] {
	return func(out chan<- *model.PlaintextRecord) {
		ptlog.Info("Plaintext tracer started")
		for {
			select {
			case <-ctx.Done():
				ptlog.Debug("exiting plaintext trace loop")
				return
			default:
				if err := m.listenAndForward(out); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					ptlog.WithError(err).Warn("ignoring plaintext event")
				}
			}
		}
	}
}

func (m *PlaintextTracer) listenAndForward(forwardCh chan<- *model.PlaintextRecord) error {
	event, err := m.reader.ReadSSLRingBuf()
	if err != nil {
		if m.metrics != nil {
			m.metrics.Errors.WithErrorName("ringbuffer", "CannotReadSSLRingbuffer", metrics.HighSeverity).Inc()
		}
		return fmt.Errorf("reading SSL ring buffer: %w", err)
	}

	rec, err := model.ReadPlaintextFrom(bytes.NewBuffer(event.RawSample))
	if err != nil {
		if m.metrics != nil {
			m.metrics.Errors.WithErrorName("ringbuffer", "CannotParseSSLRingbuffer", metrics.HighSeverity).Inc()
		}
		return fmt.Errorf("parsing SSL event: %w", err)
	}

	if m.metrics != nil {
		m.metrics.OpenSSLDataEventsCounter.Increase(strconv.Itoa(int(rec.SSLType)))
	}

	if len(rec.Data) > 0 {
		ptlog.WithFields(logrus.Fields{
			"pid":       rec.Pid,
			"direction": rec.Direction,
			"bytes":     len(rec.Data),
			"source":    rec.TLSSource,
		}).Info("TLS plaintext event captured")
	}

	if m.processor != nil && !m.processor.Process(rec) {
		return nil
	}

	forwardCh <- rec
	return nil
}
