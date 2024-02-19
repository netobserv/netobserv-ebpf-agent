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
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/encode"
	putils "github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// TODO: Refactor the code that is common with encode_prom
const (
	defaultExpiryTime = time.Duration(2 * time.Minute)
	flpMeterName      = "flp_meter"
)

type counterInfo struct {
	counter *metric.Float64Counter
	info    *encode.MetricInfo
}

type gaugeInfo struct {
	gauge *metric.Float64ObservableGauge
	info  *encode.MetricInfo
	obs   Float64Gauge
}

// TBD: Handle histograms
/*
type histoInfo struct {
	histo *metric.Float64Histogram
	info  *encode.MetricInfo
}
*/

type EncodeOtlpMetrics struct {
	cfg      api.EncodeOtlpMetrics
	ctx      context.Context
	res      *resource.Resource
	mp       *sdkmetric.MeterProvider
	counters []counterInfo
	gauges   []gaugeInfo
	//histos           []histoInfo
	//aggHistos        []histoInfo
	expiryTime       time.Duration
	mCache           *putils.TimedCache
	exitChan         <-chan struct{}
	meter            metric.Meter
	metricsProcessed prometheus.Counter
	metricsDropped   prometheus.Counter
	errorsCounter    *prometheus.CounterVec
}

// Encode encodes a metric to be exported
func (e *EncodeOtlpMetrics) Encode(metricRecord config.GenericMap) {
	log.Tracef("entering EncodeOtlpMetrics. entry = %v", metricRecord)

	// Process counters
	for _, mInfo := range e.counters {
		labels, value, _ := e.prepareMetric(metricRecord, mInfo.info)
		if labels == nil {
			continue
		}
		// set attributes using the labels
		attributes := obtainAttributesFromLabels(labels)
		(*mInfo.counter).Add(e.ctx, value, metric.WithAttributes(attributes...))
		e.metricsProcessed.Inc()
	}

	// Process gauges
	for _, mInfo := range e.gauges {
		labels, value, key := e.prepareMetric(metricRecord, mInfo.info)
		if labels == nil {
			continue
		}
		// set attributes using the labels
		attributes := obtainAttributesFromLabels(labels)
		mInfo.obs.Set(key, value, attributes)
		e.metricsProcessed.Inc()
	}
	// TBD: Process histograms
}

func (e *EncodeOtlpMetrics) prepareMetric(flow config.GenericMap, info *encode.MetricInfo) (map[string]string, float64, string) {
	val := e.extractGenericValue(flow, info)
	if val == nil {
		return nil, 0, ""
	}
	floatVal, err := utils.ConvertToFloat64(val)
	if err != nil {
		e.errorsCounter.WithLabelValues("ValueConversionError", info.Name, info.ValueKey).Inc()
		return nil, 0, ""
	}

	entryLabels, key := encode.ExtractLabelsAndKey(flow, &info.MetricsItem)
	// Update entry for expiry mechanism (the entry itself is its own cleanup function)
	_, ok := e.mCache.UpdateCacheEntry(key, entryLabels)
	if !ok {
		e.metricsDropped.Inc()
		return nil, 0, ""
	}
	return entryLabels, floatVal, key
}

func (e *EncodeOtlpMetrics) extractGenericValue(flow config.GenericMap, info *encode.MetricInfo) interface{} {
	for _, pred := range info.FilterPredicates {
		if !pred(flow) {
			return nil
		}
	}
	if info.ValueKey == "" {
		// No value key means it's a records / flows counter (1 flow = 1 increment), so just return 1
		return 1
	}
	val, found := flow[info.ValueKey]
	if !found {
		e.errorsCounter.WithLabelValues("RecordKeyMissing", info.Name, info.ValueKey).Inc()
		return nil
	}
	return val
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

	mp, err := NewOtlpMetricsProvider(ctx, params, res)
	if err != nil {
		return nil, err
	}
	meter := mp.Meter(
		flpMeterName,
	)

	expiryTime := cfg.ExpiryTime
	if expiryTime.Duration == 0 {
		expiryTime.Duration = defaultExpiryTime
	}

	meterFactory := otel.Meter(flpMeterName)
	counters := []counterInfo{}
	gauges := []gaugeInfo{}

	for _, mCfg := range cfg.Metrics {
		fullMetricName := cfg.Prefix + mCfg.Name
		labels := mCfg.Labels
		log.Debugf("fullMetricName = %v", fullMetricName)
		log.Debugf("Labels = %v", labels)
		mInfo := encode.CreateMetricInfo(mCfg)
		switch mCfg.Type {
		case api.MetricEncodeOperationName("Counter"):
			counter, err := meter.Float64Counter(fullMetricName)
			if err != nil {
				log.Errorf("error during counter creation: %v", err)
				return nil, err
			}
			counters = append(counters, counterInfo{
				counter: &counter,
				info:    mInfo,
			})
		case api.MetricEncodeOperationName("Gauge"):
			// at implementation time, only asynchronous gauges are supported by otel in golang
			obs := Float64Gauge{observations: make(map[string]Float64GaugeEntry)}
			gauge, err := meterFactory.Float64ObservableGauge(
				fullMetricName,
				metric.WithFloat64Callback(obs.Callback),
			)
			if err != nil {
				log.Errorf("error during gauge creation: %v", err)
				return nil, err
			}
			gInfo := gaugeInfo{
				info:  mInfo,
				obs:   obs,
				gauge: &gauge,
			}
			gauges = append(gauges, gInfo)
		// TBD: handle histograms
		case "default":
			log.Errorf("invalid metric type = %v, skipping", mCfg.Type)
			continue
		}
	}

	w := &EncodeOtlpMetrics{
		cfg:              cfg,
		ctx:              ctx,
		res:              res,
		mp:               mp,
		meter:            meterFactory,
		counters:         counters,
		gauges:           gauges,
		expiryTime:       expiryTime.Duration,
		mCache:           putils.NewTimedCache(0, nil),
		exitChan:         putils.ExitChannel(),
		metricsProcessed: opMetrics.NewCounter(&encode.MetricsProcessed, params.Name),
		metricsDropped:   opMetrics.NewCounter(&encode.MetricsDropped, params.Name),
		errorsCounter:    opMetrics.NewCounterVec(&encode.EncodePromErrors),
	}
	go w.cleanupExpiredEntriesLoop()
	return w, nil
}

// Cleanup - callback function from lru cleanup
func (e *EncodeOtlpMetrics) Cleanup(cleanupFunc interface{}) {
	// nothing more to do
}

func (e *EncodeOtlpMetrics) cleanupExpiredEntriesLoop() {
	ticker := time.NewTicker(e.expiryTime)
	for {
		select {
		case <-e.exitChan:
			log.Debugf("exiting cleanupExpiredEntriesLoop because of signal")
			return
		case <-ticker.C:
			e.mCache.CleanupExpiredEntries(e.expiryTime, e.Cleanup)
		}
	}
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
func (f *Float64Gauge) Callback(ctx context.Context, o metric.Float64Observer) error {
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
