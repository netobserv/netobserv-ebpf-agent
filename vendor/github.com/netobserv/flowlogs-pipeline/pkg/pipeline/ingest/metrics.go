package ingest

import (
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	latencyHistogram = operational.DefineMetric(
		"ingest_latency_ms",
		"Latency between flow end time and ingest time, in milliseconds",
		operational.TypeHistogram,
		"stage",
	)
	flowsProcessedCounter = operational.DefineMetric(
		"ingest_flows_processed",
		"Number of flows received by the ingester",
		operational.TypeCounter,
		"stage",
	)
	batchSizeBytesSummary = operational.DefineMetric(
		"ingest_batch_size_bytes",
		"Ingested batch size distribution, in bytes",
		operational.TypeSummary,
		"stage",
	)
	errorsCounter = operational.DefineMetric(
		"ingest_errors",
		"Counter of errors during ingestion",
		operational.TypeCounter,
		"stage", "type", "code",
	)
)

type metrics struct {
	*operational.Metrics
	stage          string
	stageType      string
	stageDuration  prometheus.Observer
	latency        prometheus.Histogram
	flowsProcessed prometheus.Counter
	batchSizeBytes prometheus.Summary
	errors         *prometheus.CounterVec
}

func newMetrics(opMetrics *operational.Metrics, stage, stageType string, inGaugeFunc func() int, opts ...metricsOption) *metrics {
	opMetrics.CreateInQueueSizeGauge(stage, inGaugeFunc)
	ret := &metrics{
		Metrics:        opMetrics,
		stage:          stage,
		stageType:      stageType,
		flowsProcessed: opMetrics.NewCounter(&flowsProcessedCounter, stage),
		errors:         opMetrics.NewCounterVec(&errorsCounter),
	}
	for _, opt := range opts {
		ret = opt(ret)
	}
	return ret
}

type metricsOption func(*metrics) *metrics

func withStageDuration() metricsOption {
	return func(m *metrics) *metrics {
		if m.stageDuration == nil {
			m.stageDuration = m.GetOrCreateStageDurationHisto().WithLabelValues(m.stage)
		}
		return m
	}
}

func withLatency() metricsOption {
	return func(m *metrics) *metrics {
		if m.latency == nil {
			m.latency = m.NewHistogram(&latencyHistogram, []float64{.001, .01, .1, 1, 10, 100, 1000, 10000}, m.stage)
		}
		return m
	}
}

func withBatchSizeBytes() metricsOption {
	return func(m *metrics) *metrics {
		if m.batchSizeBytes == nil {
			m.batchSizeBytes = m.NewSummary(&batchSizeBytesSummary, m.stage)
		}
		return m
	}
}

func (m *metrics) createOutQueueLen(out chan<- config.GenericMap) {
	m.CreateOutQueueSizeGauge(m.stage, func() int { return len(out) })
}

// Increment error counter
// `code` should reflect any error code relative to this type. It can be a short string message,
// but make sure to not include any dynamic value with high cardinality
func (m *metrics) error(code string) {
	m.errors.WithLabelValues(m.stage, m.stageType, code).Inc()
}

func (m *metrics) stageDurationTimer() *operational.Timer {
	return operational.NewTimer(m.stageDuration)
}

func (m *metrics) observeLatency(record config.GenericMap) {
	if m.latency == nil {
		return
	}
	tfeUnknown, ok := record["TimeFlowEndMs"]
	if !ok {
		m.error("TimeFlowEndMs missing")
		return
	}
	var tfe int64
	switch i := tfeUnknown.(type) {
	case int64:
		tfe = i
	case int:
		tfe = int64(i)
	case uint64:
		tfe = int64(i)
	case uint:
		tfe = int64(i)
	default:
		m.error("Cannot parse TimeFlowEndMs")
		return
	}
	delay := time.Since(time.UnixMilli(tfe)).Seconds()
	m.latency.Observe(delay)
}
