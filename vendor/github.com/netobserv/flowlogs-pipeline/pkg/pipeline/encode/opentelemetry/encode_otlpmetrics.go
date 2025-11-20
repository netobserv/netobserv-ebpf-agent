/*
 * Copyright (C) 2023 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package opentelemetry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/encode"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/encode/metrics"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const defaultExpiryTime = time.Duration(2 * time.Minute)
const flpMeterName = "flp_meter"

type EncodeOtlpMetrics struct {
	cfg          api.EncodeOtlpMetrics
	ctx          context.Context
	metricCommon *encode.MetricsCommonStruct
}

func (e *EncodeOtlpMetrics) Update(_ config.StageParam) {
	log.Warn("EncodeOtlpMetrics, update not supported")
}

// Encode encodes a metric to be exported
func (e *EncodeOtlpMetrics) Encode(metricRecord config.GenericMap) {
	log.Tracef("entering EncodeOtlpMetrics. entry = %v", metricRecord)
	e.metricCommon.MetricCommonEncode(e, metricRecord)
}

func (e *EncodeOtlpMetrics) ProcessCounter(m interface{}, name string, labels map[string]string, value float64) error {
	if counter, ok := m.(metric.Float64Counter); ok {
		// set attributes using the labels
		attributes := obtainAttributesFromLabels(labels)
		counter.Add(e.ctx, value, metric.WithAttributes(attributes...))
		return nil
	}
	return fmt.Errorf("wrong Otlp Counter type for %s: %T; expecting Float64Counter", name, m)
}

func createKey(name string, keys []string) string {
	key := strings.Builder{}
	key.WriteString(name)
	key.WriteRune('|')
	for _, k := range keys {
		key.WriteString(k)
		key.WriteRune('|')
	}
	return key.String()
}

func (e *EncodeOtlpMetrics) ProcessGauge(m interface{}, name string, labels map[string]string, value float64, lvs []string) error {
	if obs, ok := m.(Float64Gauge); ok {
		// set attributes using the labels
		attributes := obtainAttributesFromLabels(labels)
		key := createKey(name, lvs)
		obs.Set(key, value, attributes)
		return nil
	}
	return fmt.Errorf("wrong Otlp Gauge type for %s: %T; expecting Float64Gauge", name, m)
}

func (e *EncodeOtlpMetrics) ProcessHist(m interface{}, name string, labels map[string]string, value float64) error {
	if histo, ok := m.(metric.Float64Histogram); ok {
		// set attributes using the labels
		attributes := obtainAttributesFromLabels(labels)
		histo.Record(e.ctx, value, metric.WithAttributes(attributes...))
		return nil
	}
	return fmt.Errorf("wrong Otlp Histogram type for %s: %T; expecting Float64Histogram", name, m)
}

func (e *EncodeOtlpMetrics) ProcessAggHist(m interface{}, name string, labels map[string]string, values []float64) error {
	if histo, ok := m.(metric.Float64Histogram); ok {
		// set attributes using the labels
		attributes := obtainAttributesFromLabels(labels)
		for _, v := range values {
			histo.Record(e.ctx, v, metric.WithAttributes(attributes...))
		}
		return nil
	}
	return fmt.Errorf("wrong Otlp Histogram type for %s: %T; expecting Float64Histogram", name, m)
}

func (e *EncodeOtlpMetrics) GetCacheEntry(entryLabels map[string]string, _ interface{}) interface{} {
	return entryLabels
}

func NewEncodeOtlpMetrics(opMetrics *operational.Metrics, params config.StageParam) (encode.Encoder, error) {
	log.Tracef("entering NewEncodeOtlpMetrics \n")
	cfg := api.EncodeOtlpMetrics{}
	if params.Encode != nil && params.Encode.OtlpMetrics != nil {
		cfg = *params.Encode.OtlpMetrics
	}
	log.Debugf("NewEncodeOtlpMetrics cfg = %v \n", cfg)

	ctx := context.Background()
	res := newResource()

	mp, err := NewOtlpMetricsProvider(ctx, &cfg, res)
	if err != nil {
		return nil, err
	}
	meter := mp.Meter(flpMeterName)
	return newEncodeOtlpMetricsWithMeter(ctx, params.Name, opMetrics, &cfg, meter)
}

func newEncodeOtlpMetricsWithMeter(ctx context.Context, stageName string, opMetrics *operational.Metrics, cfg *api.EncodeOtlpMetrics, meter metric.Meter) (encode.Encoder, error) {
	meterFactory := otel.Meter(flpMeterName)

	expiryTime := cfg.ExpiryTime
	if expiryTime.Duration == 0 {
		expiryTime.Duration = defaultExpiryTime
	}

	w := &EncodeOtlpMetrics{
		cfg: *cfg,
		ctx: ctx,
	}

	metricCommon := encode.NewMetricsCommonStruct(opMetrics, 0, stageName, expiryTime, nil)
	w.metricCommon = metricCommon

	for i := range cfg.Metrics {
		mCfg := &cfg.Metrics[i]
		fullMetricName := cfg.Prefix + mCfg.Name
		log.Debugf("fullMetricName = %v", fullMetricName)
		log.Debugf("Labels = %v", mCfg.Labels)
		mInfo := metrics.Preprocess(mCfg)
		switch mCfg.Type {
		case api.MetricCounter:
			counter, err := meter.Float64Counter(fullMetricName, metric.WithDescription(mCfg.Help))
			if err != nil {
				log.Errorf("error during counter creation: %v", err)
				return nil, err
			}
			metricCommon.AddCounter(fullMetricName, counter, mInfo)
		case api.MetricGauge:
			// at implementation time, only asynchronous gauges are supported by otel in golang
			obs := Float64Gauge{observations: make(map[string]Float64GaugeEntry)}
			gauge, err := meterFactory.Float64ObservableGauge(
				fullMetricName,
				metric.WithDescription(mCfg.Help),
				metric.WithFloat64Callback(obs.Callback),
			)
			if err != nil {
				log.Errorf("error during gauge creation: %v", err)
				return nil, err
			}
			metricCommon.AddGauge(fullMetricName, gauge, mInfo)
		case api.MetricHistogram:
			var histo metric.Float64Histogram
			var err error
			if len(mCfg.Buckets) == 0 {
				histo, err = meter.Float64Histogram(fullMetricName, metric.WithDescription(mCfg.Help))
			} else {
				histo, err = meter.Float64Histogram(fullMetricName,
					metric.WithDescription(mCfg.Help),
					metric.WithExplicitBucketBoundaries(mCfg.Buckets...),
				)
			}
			if err != nil {
				log.Errorf("error during histogram creation: %v", err)
				return nil, err
			}
			metricCommon.AddHist(fullMetricName, histo, mInfo)
		case api.MetricAggHistogram:
			fallthrough
		default:
			log.Errorf("invalid metric type = %v, skipping", mCfg.Type)
			continue
		}
	}

	return w, nil
}

// At present, golang only supports asynchronous gauge, so we have some function here to support this

type Float64GaugeEntry struct {
	attributes []attribute.KeyValue
	value      float64
}

type Float64Gauge struct {
	observations map[string]Float64GaugeEntry
}

// Callback implements the callback function for the underlying asynchronous gauge
// it observes the current state of all previous Set() calls.
func (f *Float64Gauge) Callback(_ context.Context, o metric.Float64Observer) error {
	for _, fEntry := range f.observations {
		o.Observe(fEntry.value, metric.WithAttributes(fEntry.attributes...))
	}
	// re-initialize the observed items
	f.observations = make(map[string]Float64GaugeEntry)
	return nil
}

func (f *Float64Gauge) Set(key string, val float64, attrs []attribute.KeyValue) {
	f.observations[key] = Float64GaugeEntry{
		value:      val,
		attributes: attrs,
	}
}
