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
}

// Encode encodes a metric before being stored; the heavy work is done by the MetricCommonEncode
func (e *EncodeProm) Encode(metricRecord config.GenericMap) {
	log.Tracef("entering EncodeMetric. metricRecord = %v", metricRecord)
	e.metricCommon.MetricCommonEncode(e, metricRecord)
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
			metricCommon.AddCounter(counter, mInfo)
		case api.MetricGauge:
			gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: fullMetricName, Help: ""}, labels)
			err := registerer.Register(gauge)
			if err != nil {
				log.Errorf("error during prometheus.Register: %v", err)
				return nil, err
			}
			metricCommon.AddGauge(gauge, mInfo)
		case api.MetricHistogram:
			log.Debugf("buckets = %v", mCfg.Buckets)
			hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: fullMetricName, Help: "", Buckets: mCfg.Buckets}, labels)
			err := registerer.Register(hist)
			if err != nil {
				log.Errorf("error during prometheus.Register: %v", err)
				return nil, err
			}
			metricCommon.AddHist(hist, mInfo)
		case api.MetricAggHistogram:
			log.Debugf("buckets = %v", mCfg.Buckets)
			hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: fullMetricName, Help: "", Buckets: mCfg.Buckets}, labels)
			err := registerer.Register(hist)
			if err != nil {
				log.Errorf("error during prometheus.Register: %v", err)
				return nil, err
			}
			metricCommon.AddAggHist(hist, mInfo)
		case "default":
			log.Errorf("invalid metric type = %v, skipping", mCfg.Type)
			continue
		}
	}
	return w, nil
}
