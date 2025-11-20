package metrics

import (
	"sync"
	"time"

	"github.com/netobserv/loki-client-go/pkg/metric"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	LatencyLabel = "filename"
	HostLabel    = "host"
	MetricPrefix = "netobserv"
)

var (
	// Shared metrics for both HTTP and gRPC clients
	EncodedBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricPrefix,
		Name:      "loki_encoded_bytes_total",
		Help:      "Number of bytes encoded and ready to send.",
	}, []string{HostLabel, "transport"})

	SentBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricPrefix,
		Name:      "loki_sent_bytes_total",
		Help:      "Number of bytes sent.",
	}, []string{HostLabel, "transport"})

	DroppedBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricPrefix,
		Name:      "loki_dropped_bytes_total",
		Help:      "Number of bytes dropped because failed to be sent to the ingester after all retries.",
	}, []string{HostLabel, "transport"})

	SentEntries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricPrefix,
		Name:      "loki_sent_entries_total",
		Help:      "Number of log entries sent to the ingester.",
	}, []string{HostLabel, "transport"})

	DroppedEntries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricPrefix,
		Name:      "loki_dropped_entries_total",
		Help:      "Number of log entries dropped because failed to be sent to the ingester after all retries.",
	}, []string{HostLabel, "transport"})

	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: MetricPrefix,
		Name:      "loki_request_duration_seconds",
		Help:      "Duration of send requests.",
	}, []string{"status_code", HostLabel, "transport"})

	BatchRetries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricPrefix,
		Name:      "loki_batch_retries_total",
		Help:      "Number of times batches has had to be retried.",
	}, []string{HostLabel, "transport"})


	StreamLag *metric.Gauges

	// CountersWithHost are the counters that have host as a label
	CountersWithHost = []*prometheus.CounterVec{
		EncodedBytes, SentBytes, DroppedBytes, SentEntries, DroppedEntries, BatchRetries,
	}

	registrationOnce sync.Once
)

// RegisterMetrics registers all metrics with prometheus
func RegisterMetrics() {
	registrationOnce.Do(func() {
		prometheus.MustRegister(EncodedBytes)
		prometheus.MustRegister(SentBytes)
		prometheus.MustRegister(DroppedBytes)
		prometheus.MustRegister(SentEntries)
		prometheus.MustRegister(DroppedEntries)
		prometheus.MustRegister(RequestDuration)
		prometheus.MustRegister(BatchRetries)

		var err error
		StreamLag, err = metric.NewGauges(MetricPrefix+"_stream_lag_seconds",
			"Difference between current time and last batch timestamp for successful sends",
			metric.GaugeConfig{Action: "set"},
			int64(1*time.Minute.Seconds()),
		)
		if err != nil {
			panic(err)
		}
		prometheus.MustRegister(StreamLag)
	})
}
