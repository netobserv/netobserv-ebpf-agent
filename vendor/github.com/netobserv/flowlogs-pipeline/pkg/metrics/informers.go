package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	// InformersMetrics holds all Prometheus metrics for flp-informers
	InformersMetrics *Metrics
)

// Metrics holds all Prometheus metrics
type Metrics struct {
	IsLeader                prometheus.Gauge
	ConnectedProcessors     prometheus.Gauge
	CacheUpdatesTotal       *prometheus.CounterVec
	CacheSnapshotsSentTotal prometheus.Counter
	ErrorsTotal             *prometheus.CounterVec
	// gRPC communication metrics
	GrpcBytesSentTotal    prometheus.Counter
	GrpcBytesRecvTotal    prometheus.Counter
	GrpcMessagesSentTotal prometheus.Counter
	GrpcMessagesRecvTotal prometheus.Counter
	// Processor lifecycle metrics
	ProcessorConnectionsTotal *prometheus.CounterVec
	ProcessorLifetimeDuration prometheus.Histogram
	// UDN disambiguation metrics
	UdnDisambiguateTotal    prometheus.Counter
	UdnDisambiguateDuration prometheus.Histogram
}

// InitMetrics initializes all Prometheus metrics
func InitMetrics() {
	InformersMetrics = &Metrics{
		IsLeader: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flp_informers_is_leader",
			Help: "1 if this instance is the current leader, 0 otherwise",
		}),
		ConnectedProcessors: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flp_informers_connected_processors",
			Help: "Number of FLP processors currently connected",
		}),
		CacheUpdatesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "flp_informers_cache_updates_total",
				Help: "Total number of cache updates sent to processors",
			},
			[]string{"operation"}, // ADD, UPDATE, DELETE, SNAPSHOT
		),
		CacheSnapshotsSentTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flp_informers_snapshots_sent_total",
			Help: "Total number of full snapshots sent to processors",
		}),
		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "flp_informers_errors_total",
				Help: "Total number of errors by type",
			},
			[]string{"error_type"}, // discovery, udn_disambiguation
		),
		// gRPC communication metrics
		GrpcBytesSentTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flp_informers_grpc_bytes_sent_total",
			Help: "Total number of bytes sent via gRPC to processors",
		}),
		GrpcBytesRecvTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flp_informers_grpc_bytes_received_total",
			Help: "Total number of bytes received via gRPC from processors",
		}),
		GrpcMessagesSentTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flp_informers_grpc_messages_sent_total",
			Help: "Total number of gRPC messages sent to processors",
		}),
		GrpcMessagesRecvTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flp_informers_grpc_messages_received_total",
			Help: "Total number of gRPC messages received from processors",
		}),
		// Processor lifecycle metrics
		ProcessorConnectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "flp_informers_processor_connections_total",
				Help: "Total number of processor connection events",
			},
			[]string{"event"}, // connected, disconnected, reconnected
		),
		ProcessorLifetimeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "flp_informers_processor_lifetime_duration_seconds",
			Help:    "Duration of processor connections in seconds",
			Buckets: []float64{1, 10, 30, 60, 300, 600, 1800, 3600, 7200}, // 1s to 2h
		}),
		// UDN disambiguation metrics
		UdnDisambiguateTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flp_informers_udn_disambiguate_total",
			Help: "Total number of UDN disambiguation attempts",
		}),
		UdnDisambiguateDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "flp_informers_udn_disambiguate_duration_seconds",
			Help:    "Duration of UDN disambiguation operations in seconds",
			Buckets: prometheus.DefBuckets, // 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
		}),
	}

	// Register all metrics
	prometheus.MustRegister(
		InformersMetrics.IsLeader,
		InformersMetrics.ConnectedProcessors,
		InformersMetrics.CacheUpdatesTotal,
		InformersMetrics.CacheSnapshotsSentTotal,
		InformersMetrics.ErrorsTotal,
		InformersMetrics.GrpcBytesSentTotal,
		InformersMetrics.GrpcBytesRecvTotal,
		InformersMetrics.GrpcMessagesSentTotal,
		InformersMetrics.GrpcMessagesRecvTotal,
		InformersMetrics.ProcessorConnectionsTotal,
		InformersMetrics.ProcessorLifetimeDuration,
		InformersMetrics.UdnDisambiguateTotal,
		InformersMetrics.UdnDisambiguateDuration,
	)
}

// Server provides HTTP endpoint for Prometheus metrics
type Server struct {
	server *http.Server
}

// NewServer creates a new metrics server listening on the specified port
func NewServer(port int) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	return &Server{
		server: &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		},
	}
}

// Start starts the metrics server in a goroutine
func (ms *Server) Start() error {
	log.WithField("address", ms.server.Addr).Info("Starting metrics server")

	go func() {
		if err := ms.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("Metrics server error")
		}
	}()

	return nil
}

// Stop stops the metrics server gracefully
func (ms *Server) Stop() error {
	log.Info("Stopping metrics server")
	return ms.server.Close()
}
