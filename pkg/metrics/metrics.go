package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

type MetricDefinition struct {
	Name   string
	Help   string
	Type   metricType
	Labels []string
}

type PromConnectionInfo struct {
	Address string
	Port    int
}

type Settings struct {
	PromConnectionInfo
	Prefix string
}

type metricType string

const (
	TypeCounter   metricType = "counter"
	TypeGauge     metricType = "gauge"
	TypeHistogram metricType = "histogram"
)

var allMetrics = []MetricDefinition{}

func defineMetric(name, help string, t metricType, labels ...string) MetricDefinition {
	def := MetricDefinition{
		Name:   name,
		Help:   help,
		Type:   t,
		Labels: labels,
	}
	allMetrics = append(allMetrics, def)
	return def
}

var (
	hmapEvictionsTotal = defineMetric(
		"hashmap_evictions_total",
		"Number of hashmap evictions total",
		TypeCounter,
	)
	userspaceNumberOfEvictionsTotal = defineMetric(
		"userspace_number_of_evictions_total",
		"Number of userspace evictions total",
		TypeCounter,
	)
	numberOfevictedFlowsTotal = defineMetric(
		"number_of_evicted_flows_total",
		"Number of evicted flows Total",
		TypeCounter,
	)
	numberofFlowsreceivedviaRingBufferTotal = defineMetric(
		"number_of_flows_received_via_ring_buffer_total",
		"Number of flows received via ring buffer total",
		TypeCounter,
	)
	lookupAndDeleteMapDurationSeconds = defineMetric(
		"lookup_and_delete_map_duration_seconds",
		"Lookup and delete map duration seconds",
		TypeHistogram,
	)
	numberOfWrittenRecordsTotal = defineMetric(
		"number_of_written_records_total",
		"Number of written records total",
		TypeCounter,
		"exporter",
	)
	exportedBatchSizeTotal = defineMetric(
		"exported_batch_size_total",
		"Exported batch size total",
		TypeCounter,
		"exporter",
	)
	samplingRateSeconds = defineMetric(
		"sampling_rate_seconds",
		"Sampling rate seconds",
		TypeGauge,
	)
	errorsCounter = defineMetric(
		"errors_total",
		"errors counter",
		TypeCounter,
		"error",
		"exporter",
	)
)

func (def *MetricDefinition) mapLabels(labels []string) prometheus.Labels {
	if len(labels) != len(def.Labels) {
		logrus.Errorf("Could not map labels, length differ in def %s [%v / %v]", def.Name, def.Labels, labels)
	}
	labelsMap := prometheus.Labels{}
	for i, label := range labels {
		labelsMap[def.Labels[i]] = label
	}
	return labelsMap
}

func verifyMetricType(def *MetricDefinition, t metricType) {
	if def.Type != t {
		logrus.Panicf("operational metric %q is of type %q but is being registered as %q", def.Name, def.Type, t)
	}
}

type Metrics struct {
	Settings *Settings
}

func NewMetrics(settings *Settings) *Metrics {
	return &Metrics{Settings: settings}
}

// register will register against the default registry. May panic or not depending on settings
func (m *Metrics) register(c prometheus.Collector, name string) {
	err := prometheus.DefaultRegisterer.Register(c)
	if err != nil {
		if errors.As(err, &prometheus.AlreadyRegisteredError{}) {
			logrus.Warningf("metrics registration error [%s]: %v", name, err)
		} else {
			logrus.Panicf("metrics registration error [%s]: %v", name, err)
		}
	}
}

func (m *Metrics) NewCounter(def *MetricDefinition, labels ...string) prometheus.Counter {
	verifyMetricType(def, TypeCounter)
	fullName := m.Settings.Prefix + def.Name
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        fullName,
		Help:        def.Help,
		ConstLabels: def.mapLabels(labels),
	})
	m.register(c, fullName)
	return c
}

func (m *Metrics) NewCounterVec(def *MetricDefinition) *prometheus.CounterVec {
	verifyMetricType(def, TypeCounter)
	fullName := m.Settings.Prefix + def.Name
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: fullName,
		Help: def.Help,
	}, def.Labels)
	m.register(c, fullName)
	return c
}

func (m *Metrics) NewGauge(def *MetricDefinition, labels ...string) prometheus.Gauge {
	verifyMetricType(def, TypeGauge)
	fullName := m.Settings.Prefix + def.Name
	c := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        fullName,
		Help:        def.Help,
		ConstLabels: def.mapLabels(labels),
	})
	m.register(c, fullName)
	return c
}

func (m *Metrics) NewHistogram(def *MetricDefinition, buckets []float64, labels ...string) prometheus.Histogram {
	verifyMetricType(def, TypeHistogram)
	fullName := m.Settings.Prefix + def.Name
	c := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        fullName,
		Help:        def.Help,
		Buckets:     buckets,
		ConstLabels: def.mapLabels(labels),
	})
	m.register(c, fullName)
	return c
}

func (m *Metrics) CreateHashMapCounter() prometheus.Counter {
	return m.NewCounter(&hmapEvictionsTotal)
}

func (m *Metrics) CreateUserSpaceEvictionCounter() prometheus.Counter {
	return m.NewCounter(&userspaceNumberOfEvictionsTotal)
}

func (m *Metrics) CreateNumberOfEvictedFlows() prometheus.Counter {
	return m.NewCounter(&numberOfevictedFlowsTotal)
}

func (m *Metrics) CreateNumberOfFlowsReceivedByRingBuffer() prometheus.Counter {
	return m.NewCounter(&numberofFlowsreceivedviaRingBufferTotal)
}

func (m *Metrics) CreateTimeSpendInLookupAndDelete() prometheus.Histogram {
	return m.NewHistogram(&lookupAndDeleteMapDurationSeconds, []float64{.001, .01, .1, 1, 10, 100, 1000, 10000})
}

func (m *Metrics) CreateNumberOfRecordsExportedByGRPC() prometheus.Counter {
	return m.NewCounter(&numberOfWrittenRecordsTotal, "grpc")
}

func (m *Metrics) CreateGRPCBatchSize() prometheus.Counter {
	return m.NewCounter(&exportedBatchSizeTotal, "grpc")
}

func (m *Metrics) CreateNumberOfRecordsExportedByKafka() prometheus.Counter {
	return m.NewCounter(&numberOfWrittenRecordsTotal, "kafka")
}

func (m *Metrics) CreateKafkaBatchSize() prometheus.Counter {
	return m.NewCounter(&exportedBatchSizeTotal, "kafka")
}

func (m *Metrics) CreateSamplingRate() prometheus.Gauge {
	return m.NewGauge(&samplingRateSeconds)
}

func (m *Metrics) GetErrorsCounter() *ErrorCounter {
	return &ErrorCounter{
		vec: m.NewCounterVec(&errorsCounter),
	}
}

type ErrorCounter struct {
	vec *prometheus.CounterVec
}

func (c *ErrorCounter) WithValues(errName, exporter string) prometheus.Counter {
	return c.vec.WithLabelValues(errName, exporter)
}
