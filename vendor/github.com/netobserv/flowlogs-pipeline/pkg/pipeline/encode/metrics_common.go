/*
 * Copyright (C) 2024 IBM, Inc.
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

package encode

import (
	"fmt"
	"strings"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	putils "github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type mInfoStruct struct {
	genericMetric interface{} // can be a counter, gauge, or histogram pointer
	info          *MetricInfo
}

type MetricsCommonStruct struct {
	gauges           []mInfoStruct
	counters         []mInfoStruct
	histos           []mInfoStruct
	aggHistos        []mInfoStruct
	mCache           *putils.TimedCache
	mChacheLenMetric prometheus.Gauge
	metricsProcessed prometheus.Counter
	metricsDropped   prometheus.Counter
	errorsCounter    *prometheus.CounterVec
	expiryTime       time.Duration
	exitChan         <-chan struct{}
}

type MetricsCommonInterface interface {
	GetChacheEntry(entryLabels map[string]string, m interface{}) interface{}
	ProcessCounter(m interface{}, labels map[string]string, value float64) error
	ProcessGauge(m interface{}, labels map[string]string, value float64, key string) error
	ProcessHist(m interface{}, labels map[string]string, value float64) error
	ProcessAggHist(m interface{}, labels map[string]string, value []float64) error
}

var (
	metricsProcessed = operational.DefineMetric(
		"metrics_processed",
		"Number of metrics processed",
		operational.TypeCounter,
		"stage",
	)
	metricsDropped = operational.DefineMetric(
		"metrics_dropped",
		"Number of metrics dropped",
		operational.TypeCounter,
		"stage",
	)
	encodePromErrors = operational.DefineMetric(
		"encode_prom_errors",
		"Total errors during metrics generation",
		operational.TypeCounter,
		"error", "metric", "key",
	)
	mChacheLen = operational.DefineMetric(
		"encode_prom_metrics_reported",
		"Total number of prometheus metrics reported by this stage",
		operational.TypeGauge,
		"stage",
	)
)

func (m *MetricsCommonStruct) AddCounter(g interface{}, info *MetricInfo) {
	mStruct := mInfoStruct{genericMetric: g, info: info}
	m.counters = append(m.counters, mStruct)
}

func (m *MetricsCommonStruct) AddGauge(g interface{}, info *MetricInfo) {
	mStruct := mInfoStruct{genericMetric: g, info: info}
	m.gauges = append(m.gauges, mStruct)
}

func (m *MetricsCommonStruct) AddHist(g interface{}, info *MetricInfo) {
	mStruct := mInfoStruct{genericMetric: g, info: info}
	m.histos = append(m.histos, mStruct)
}

func (m *MetricsCommonStruct) AddAggHist(g interface{}, info *MetricInfo) {
	mStruct := mInfoStruct{genericMetric: g, info: info}
	m.aggHistos = append(m.aggHistos, mStruct)
}

func (m *MetricsCommonStruct) MetricCommonEncode(mci MetricsCommonInterface, metricRecord config.GenericMap) {
	log.Tracef("entering MetricCommonEncode. metricRecord = %v", metricRecord)

	// Process counters
	for _, mInfo := range m.counters {
		labels, value, _ := m.prepareMetric(mci, metricRecord, mInfo.info, mInfo.genericMetric)
		if labels == nil {
			continue
		}
		err := mci.ProcessCounter(mInfo.genericMetric, labels, value)
		if err != nil {
			log.Errorf("labels registering error on %s: %v", mInfo.info.Name, err)
			m.errorsCounter.WithLabelValues("LabelsRegisteringError", mInfo.info.Name, "").Inc()
			continue
		}
		m.metricsProcessed.Inc()
	}

	// Process gauges
	for _, mInfo := range m.gauges {
		labels, value, key := m.prepareMetric(mci, metricRecord, mInfo.info, mInfo.genericMetric)
		if labels == nil {
			continue
		}
		err := mci.ProcessGauge(mInfo.genericMetric, labels, value, key)
		if err != nil {
			log.Errorf("labels registering error on %s: %v", mInfo.info.Name, err)
			m.errorsCounter.WithLabelValues("LabelsRegisteringError", mInfo.info.Name, "").Inc()
			continue
		}
		m.metricsProcessed.Inc()
	}

	// Process histograms
	for _, mInfo := range m.histos {
		labels, value, _ := m.prepareMetric(mci, metricRecord, mInfo.info, mInfo.genericMetric)
		if labels == nil {
			continue
		}
		err := mci.ProcessHist(mInfo.genericMetric, labels, value)
		if err != nil {
			log.Errorf("labels registering error on %s: %v", mInfo.info.Name, err)
			m.errorsCounter.WithLabelValues("LabelsRegisteringError", mInfo.info.Name, "").Inc()
			continue
		}
		m.metricsProcessed.Inc()
	}

	// Process pre-aggregated histograms
	for _, mInfo := range m.aggHistos {
		labels, values := m.prepareAggHisto(mci, metricRecord, mInfo.info, mInfo.genericMetric)
		if labels == nil {
			continue
		}
		err := mci.ProcessAggHist(mInfo.genericMetric, labels, values)
		if err != nil {
			log.Errorf("labels registering error on %s: %v", mInfo.info.Name, err)
			m.errorsCounter.WithLabelValues("LabelsRegisteringError", mInfo.info.Name, "").Inc()
			continue
		}
		m.metricsProcessed.Inc()
	}
}

func (m *MetricsCommonStruct) prepareMetric(mci MetricsCommonInterface, flow config.GenericMap, info *MetricInfo, mv interface{}) (map[string]string, float64, string) {
	val := m.extractGenericValue(flow, info)
	if val == nil {
		return nil, 0, ""
	}
	floatVal, err := utils.ConvertToFloat64(val)
	if err != nil {
		m.errorsCounter.WithLabelValues("ValueConversionError", info.Name, info.ValueKey).Inc()
		return nil, 0, ""
	}
	if info.ValueScale != 0 {
		floatVal = floatVal / info.ValueScale
	}

	entryLabels, key := extractLabelsAndKey(flow, info.MetricsItem)
	// Update entry for expiry mechanism (the entry itself is its own cleanup function)
	cacheEntry := mci.GetChacheEntry(entryLabels, mv)
	ok := m.mCache.UpdateCacheEntry(key, cacheEntry)
	if !ok {
		m.metricsDropped.Inc()
		return nil, 0, ""
	}
	return entryLabels, floatVal, key
}

func (m *MetricsCommonStruct) prepareAggHisto(mci MetricsCommonInterface, flow config.GenericMap, info *MetricInfo, mc interface{}) (map[string]string, []float64) {
	val := m.extractGenericValue(flow, info)
	if val == nil {
		return nil, nil
	}
	values, ok := val.([]float64)
	if !ok {
		m.errorsCounter.WithLabelValues("HistoValueConversionError", info.Name, info.ValueKey).Inc()
		return nil, nil
	}

	entryLabels, key := extractLabelsAndKey(flow, info.MetricsItem)
	// Update entry for expiry mechanism (the entry itself is its own cleanup function)
	cacheEntry := mci.GetChacheEntry(entryLabels, mc)
	ok = m.mCache.UpdateCacheEntry(key, cacheEntry)
	if !ok {
		m.metricsDropped.Inc()
		return nil, nil
	}
	return entryLabels, values
}

func (m *MetricsCommonStruct) extractGenericValue(flow config.GenericMap, info *MetricInfo) interface{} {
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
		m.errorsCounter.WithLabelValues("RecordKeyMissing", info.Name, info.ValueKey).Inc()
		return nil
	}
	return val
}

func extractLabelsAndKey(flow config.GenericMap, info *api.MetricsItem) (map[string]string, string) {
	entryLabels := make(map[string]string, len(info.Labels))
	key := strings.Builder{}
	key.WriteString(info.Name)
	key.WriteRune('|')
	for _, t := range info.Labels {
		entryLabels[t] = ""
		if v, ok := flow[t]; ok {
			entryLabels[t] = fmt.Sprintf("%v", v)
		}
		key.WriteString(entryLabels[t])
		key.WriteRune('|')
	}
	return entryLabels, key.String()
}

func (m *MetricsCommonStruct) cleanupExpiredEntriesLoop(callback putils.CacheCallback) {
	ticker := time.NewTicker(m.expiryTime)
	for {
		select {
		case <-m.exitChan:
			log.Debugf("exiting cleanupExpiredEntriesLoop because of signal")
			return
		case <-ticker.C:
			m.mCache.CleanupExpiredEntries(m.expiryTime, callback)
		}
	}
}

func NewMetricsCommonStruct(opMetrics *operational.Metrics, maxCacheEntries int, name string, expiryTime api.Duration, callback putils.CacheCallback) *MetricsCommonStruct {
	mChacheLenMetric := opMetrics.NewGauge(&mChacheLen, name)
	m := &MetricsCommonStruct{
		mCache:           putils.NewTimedCache(maxCacheEntries, mChacheLenMetric),
		mChacheLenMetric: mChacheLenMetric,
		metricsProcessed: opMetrics.NewCounter(&metricsProcessed, name),
		metricsDropped:   opMetrics.NewCounter(&metricsDropped, name),
		errorsCounter:    opMetrics.NewCounterVec(&encodePromErrors),
		expiryTime:       expiryTime.Duration,
		exitChan:         putils.ExitChannel(),
	}
	go m.cleanupExpiredEntriesLoop(callback)
	return m
}
