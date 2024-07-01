/*
 * Copyright (C) 2021 IBM, Inc.
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
	"reflect"
	"strings"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	promserver "github.com/netobserv/flowlogs-pipeline/pkg/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const defaultExpiryTime = time.Duration(2 * time.Minute)

// nolint:revive
type EncodeProm struct {
	cfg          *api.PromEncode
	registerer   prometheus.Registerer
	metricCommon *MetricsCommonStruct
	updateChan   chan config.StageParam
}

// Encode encodes a metric before being stored; the heavy work is done by the MetricCommonEncode
func (e *EncodeProm) Encode(metricRecord config.GenericMap) {
	log.Tracef("entering EncodeMetric. metricRecord = %v", metricRecord)
	e.metricCommon.MetricCommonEncode(e, metricRecord)
	e.checkConfUpdate()
}

func (e *EncodeProm) ProcessCounter(m interface{}, labels map[string]string, value float64) error {
	counter := m.(*prometheus.CounterVec)
	mm, err := counter.GetMetricWith(labels)
	if err != nil {
		return err
	}
	mm.Add(value)
	return nil
}

func (e *EncodeProm) ProcessGauge(m interface{}, labels map[string]string, value float64, _ string) error {
	gauge := m.(*prometheus.GaugeVec)
	mm, err := gauge.GetMetricWith(labels)
	if err != nil {
		return err
	}
	mm.Set(value)
	return nil
}

func (e *EncodeProm) ProcessHist(m interface{}, labels map[string]string, value float64) error {
	hist := m.(*prometheus.HistogramVec)
	mm, err := hist.GetMetricWith(labels)
	if err != nil {
		return err
	}
	mm.Observe(value)
	return nil
}

func (e *EncodeProm) ProcessAggHist(m interface{}, labels map[string]string, values []float64) error {
	hist := m.(*prometheus.HistogramVec)
	mm, err := hist.GetMetricWith(labels)
	if err != nil {
		return err
	}
	for _, v := range values {
		mm.Observe(v)
	}
	return nil
}

func (e *EncodeProm) GetChacheEntry(entryLabels map[string]string, m interface{}) interface{} {
	switch mv := m.(type) {
	case *prometheus.CounterVec:
		return func() { mv.Delete(entryLabels) }
	case *prometheus.GaugeVec:
		return func() { mv.Delete(entryLabels) }
	case *prometheus.HistogramVec:
		return func() { mv.Delete(entryLabels) }
	}
	return nil
}

// callback function from lru cleanup
func (e *EncodeProm) Cleanup(cleanupFunc interface{}) {
	cleanupFunc.(func())()
}

func (e *EncodeProm) addCounter(fullMetricName string, mInfo *MetricInfo) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: fullMetricName, Help: ""}, mInfo.Labels)
	err := e.registerer.Register(counter)
	if err != nil {
		log.Errorf("error during prometheus.Register: %v", err)
	}
	e.metricCommon.AddCounter(fullMetricName, counter, mInfo)
}

func (e *EncodeProm) addGauge(fullMetricName string, mInfo *MetricInfo) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: fullMetricName, Help: ""}, mInfo.Labels)
	err := e.registerer.Register(gauge)
	if err != nil {
		log.Errorf("error during prometheus.Register: %v", err)
	}
	e.metricCommon.AddGauge(fullMetricName, gauge, mInfo)
}
func (e *EncodeProm) addHistogram(fullMetricName string, mInfo *MetricInfo) {
	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: fullMetricName, Help: ""}, mInfo.Labels)
	err := e.registerer.Register(histogram)
	if err != nil {
		log.Errorf("error during prometheus.Register: %v", err)
	}
	e.metricCommon.AddHist(fullMetricName, histogram, mInfo)
}
func (e *EncodeProm) addAgghistogram(fullMetricName string, mInfo *MetricInfo) {
	agghistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: fullMetricName, Help: ""}, mInfo.Labels)
	err := e.registerer.Register(agghistogram)
	if err != nil {
		log.Errorf("error during prometheus.Register: %v", err)
	}
	e.metricCommon.AddAggHist(fullMetricName, agghistogram, mInfo)
}

func (e *EncodeProm) unregisterMetric(c interface{}) {
	if c, ok := c.(prometheus.Collector); ok {
		e.registerer.Unregister(c)
	}

}

func (e *EncodeProm) cleanDeletedGeneric(newCfg api.PromEncode, metrics map[string]mInfoStruct) {
	for fullName, m := range metrics {
		if !strings.HasPrefix(fullName, newCfg.Prefix) {
			if c, ok := m.genericMetric.(prometheus.Collector); ok {
				e.registerer.Unregister(c)
			}
			e.unregisterMetric(m.genericMetric)
			delete(metrics, fullName)
		}
		metricName := strings.TrimPrefix(fullName, newCfg.Prefix)
		found := false
		for i := range newCfg.Metrics {
			if metricName == newCfg.Metrics[i].Name {
				found = true
				break
			}
		}
		if !found {
			e.unregisterMetric(m.genericMetric)
			delete(metrics, fullName)
		}
	}
}

func (e *EncodeProm) cleanDeletedMetrics(newCfg api.PromEncode) {
	e.cleanDeletedGeneric(newCfg, e.metricCommon.counters)
	e.cleanDeletedGeneric(newCfg, e.metricCommon.gauges)
	e.cleanDeletedGeneric(newCfg, e.metricCommon.histos)
	e.cleanDeletedGeneric(newCfg, e.metricCommon.aggHistos)
}

func (e *EncodeProm) checkConfUpdate() {
	select {
	case stage := <-e.updateChan:
		cfg := api.PromEncode{}
		if stage.Encode != nil && stage.Encode.Prom != nil {
			cfg = *stage.Encode.Prom
		}

		e.cleanDeletedMetrics(cfg)

		for i := range cfg.Metrics {
			fullMetricName := cfg.Prefix + cfg.Metrics[i].Name
			mInfo := CreateMetricInfo(&cfg.Metrics[i])
			switch cfg.Metrics[i].Type {
			case api.MetricCounter:
				if oldMetric, ok := e.metricCommon.counters[fullMetricName]; ok {
					if !reflect.DeepEqual(mInfo.MetricsItem, oldMetric.info.MetricsItem) {
						e.unregisterMetric(oldMetric.genericMetric)
						e.addCounter(fullMetricName, mInfo)
					}
				} else {
					// New metric
					e.addCounter(fullMetricName, mInfo)
				}
			case api.MetricGauge:
				if oldMetric, ok := e.metricCommon.gauges[fullMetricName]; ok {
					if !reflect.DeepEqual(mInfo.MetricsItem, oldMetric.info.MetricsItem) {
						e.unregisterMetric(oldMetric.genericMetric)
						e.addGauge(fullMetricName, mInfo)
					}
				} else {
					// New metric
					e.addGauge(fullMetricName, mInfo)
				}
			case api.MetricHistogram:
				if oldMetric, ok := e.metricCommon.histos[fullMetricName]; ok {
					if !reflect.DeepEqual(mInfo.MetricsItem, oldMetric.info.MetricsItem) {
						e.unregisterMetric(oldMetric.genericMetric)
						e.addHistogram(fullMetricName, mInfo)
					}
				} else {
					// New metric
					e.addHistogram(fullMetricName, mInfo)
				}
			case api.MetricAggHistogram:
				if oldMetric, ok := e.metricCommon.aggHistos[fullMetricName]; ok {
					if !reflect.DeepEqual(mInfo.MetricsItem, oldMetric.info.MetricsItem) {
						e.unregisterMetric(oldMetric.genericMetric)
						e.addAgghistogram(fullMetricName, mInfo)
					}
				} else {
					// New metric
					e.addAgghistogram(fullMetricName, mInfo)
				}
			case "default":
				log.Errorf("invalid metric type = %v, skipping", cfg.Metrics[i].Type)
				continue
			}

		}
	default:
		//Nothing to do
		return
	}
}

func NewEncodeProm(opMetrics *operational.Metrics, params config.StageParam) (Encoder, error) {
	cfg := api.PromEncode{}
	if params.Encode != nil && params.Encode.Prom != nil {
		cfg = *params.Encode.Prom
	}

	expiryTime := cfg.ExpiryTime
	if expiryTime.Duration == 0 {
		expiryTime.Duration = defaultExpiryTime
	}
	log.Debugf("expiryTime = %v", expiryTime)

	var registerer prometheus.Registerer

	if cfg.PromConnectionInfo != nil {
		registry := prometheus.NewRegistry()
		registerer = registry
		promserver.StartServerAsync(cfg.PromConnectionInfo, nil)
	} else {
		registerer = prometheus.DefaultRegisterer
	}
	w := &EncodeProm{
		cfg:        params.Encode.Prom,
		registerer: registerer,
		updateChan: make(chan config.StageParam),
	}

	metricCommon := NewMetricsCommonStruct(opMetrics, cfg.MaxMetrics, params.Name, expiryTime, w.Cleanup)
	w.metricCommon = metricCommon

	for i := range cfg.Metrics {
		mCfg := &cfg.Metrics[i]
		fullMetricName := cfg.Prefix + mCfg.Name
		labels := mCfg.Labels
		log.Debugf("fullMetricName = %v", fullMetricName)
		log.Debugf("Labels = %v", labels)
		mInfo := CreateMetricInfo(mCfg)
		switch mCfg.Type {
		case api.MetricCounter:
			counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: fullMetricName, Help: ""}, labels)
			err := registerer.Register(counter)
			if err != nil {
				log.Errorf("error during prometheus.Register: %v", err)
				return nil, err
			}
			metricCommon.AddCounter(fullMetricName, counter, mInfo)
		case api.MetricGauge:
			gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: fullMetricName, Help: ""}, labels)
			err := registerer.Register(gauge)
			if err != nil {
				log.Errorf("error during prometheus.Register: %v", err)
				return nil, err
			}
			metricCommon.AddGauge(fullMetricName, gauge, mInfo)
		case api.MetricHistogram:
			log.Debugf("buckets = %v", mCfg.Buckets)
			hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: fullMetricName, Help: "", Buckets: mCfg.Buckets}, labels)
			err := registerer.Register(hist)
			if err != nil {
				log.Errorf("error during prometheus.Register: %v", err)
				return nil, err
			}
			metricCommon.AddHist(fullMetricName, hist, mInfo)
		case api.MetricAggHistogram:
			log.Debugf("buckets = %v", mCfg.Buckets)
			hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: fullMetricName, Help: "", Buckets: mCfg.Buckets}, labels)
			err := registerer.Register(hist)
			if err != nil {
				log.Errorf("error during prometheus.Register: %v", err)
				return nil, err
			}
			metricCommon.AddAggHist(fullMetricName, hist, mInfo)
		case "default":
			log.Errorf("invalid metric type = %v, skipping", mCfg.Type)
			continue
		}
	}
	return w, nil
}

func (e *EncodeProm) Update(config config.StageParam) {
	e.updateChan <- config
}
