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
	evictionsTotal = defineMetric(
		"evictions_total",
		"Number of eviction events",
		TypeCounter,
		"source",
		"reason",
	)
	evictedFlowsTotal = defineMetric(
		"evicted_flows_total",
		"Number of evicted flows",
		TypeCounter,
		"source",
		"reason",
	)
	lookupAndDeleteMapDurationSeconds = defineMetric(
		"lookup_and_delete_map_duration_seconds",
		"Lookup and delete map duration in seconds",
		TypeHistogram,
	)
	numberOfWrittenRecordsTotal = defineMetric(
		"written_records_total",
		"Number of written records",
		TypeCounter,
		"exporter",
	)
	exportedBatchSizeTotal = defineMetric(
		"exported_batch_size_total",
		"Exported batch size",
		TypeCounter,
		"exporter",
	)
	samplingRate = defineMetric(
		"sampling_rate",
		"Sampling rate",
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

	// Shared metrics:
	evictionCounter     *EvictionCounter
	evictedFlowsCounter *EvictionCounter
	errors              *ErrorCounter
}

func NewMetrics(settings *Settings) *Metrics {
	m := &Metrics{
		Settings: settings,
	}
	m.evictionCounter = &EvictionCounter{vec: m.NewCounterVec(&evictionsTotal)}
	m.evictedFlowsCounter = &EvictionCounter{vec: m.NewCounterVec(&evictedFlowsTotal)}
	m.errors = &ErrorCounter{vec: m.NewCounterVec(&errorsCounter)}
	return m
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

func (m *Metrics) NewGaugeFunc(def *MetricDefinition, f func() float64, labels ...string) {
	verifyMetricType(def, TypeGauge)
	fullName := m.Settings.Prefix + def.Name
	gf := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        fullName,
		Help:        def.Help,
		ConstLabels: def.mapLabels(labels),
	}, f)
	m.register(gf, fullName)
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

type EvictionCounter struct {
	vec *prometheus.CounterVec
}

func (m *Metrics) GetEvictionCounter() *EvictionCounter {
	return m.evictionCounter
}

func (m *Metrics) GetEvictedFlowsCounter() *EvictionCounter {
	return m.evictedFlowsCounter
}

func (c *EvictionCounter) ForSourceAndReason(source, reason string) prometheus.Counter {
	return c.vec.WithLabelValues(source, reason)
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
	return m.NewGauge(&samplingRate)
}

func (m *Metrics) GetErrorsCounter() *ErrorCounter {
	return m.errors
}

type ErrorCounter struct {
	vec *prometheus.CounterVec
}

func (c *ErrorCounter) ForErrorAndExporter(errName, exporter string) prometheus.Counter {
	return c.vec.WithLabelValues(errName, exporter)
}

func (c *ErrorCounter) ForError(errName string) prometheus.Counter {
	return c.vec.WithLabelValues(errName, "")
}
