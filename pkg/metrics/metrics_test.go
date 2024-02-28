package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetricsCreation(t *testing.T) {
	// Create a dummy Settings struct
	settings := &Settings{
		PromConnectionInfo: PromConnectionInfo{
			Address: "localhost",
			Port:    9090,
		},
		Prefix: "test_prefix_",
	}

	// Create Metrics instance
	metrics := NewMetrics(settings)

	// Test Counter creation
	counter := metrics.CreateBatchCounter("grpc")
	assert.NotNil(t, counter)

	// Test Gauge creation
	gauge := metrics.CreateSamplingRate()
	assert.NotNil(t, gauge)

	// Test Histogram creation
	histogram := metrics.CreateTimeSpendInLookupAndDelete()
	assert.NotNil(t, histogram)
}

func TestMapLabels(t *testing.T) {
	labels := []string{"label1", "label2"}
	metric := MetricDefinition{
		Labels: labels,
	}

	mapped := metric.mapLabels([]string{"value1", "value2"})

	if mapped["label1"] != "value1" {
		t.Errorf("Expected label1 to map to value1 but got %s", mapped["label1"])
	}

	if mapped["label2"] != "value2" {
		t.Errorf("Expected label2 to map to value2 but got %s", mapped["label2"])
	}
}

func TestVerifyMetricType(t *testing.T) {
	metric := MetricDefinition{
		Name: "test",
		Type: TypeCounter,
	}

	// Should not panic
	verifyMetricType(&metric, TypeCounter)

	// Should panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected verifyMetricType to panic but it did not")
		}
	}()

	verifyMetricType(&metric, TypeGauge)
}
