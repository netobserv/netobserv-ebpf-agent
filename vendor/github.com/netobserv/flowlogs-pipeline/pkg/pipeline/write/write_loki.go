/*
 * Copyright (C) 2022 IBM, Inc.
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

package write

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	pUtils "github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils"

	logAdapter "github.com/go-kit/kit/log/logrus"
	"github.com/netobserv/loki-client-go/loki"
	"github.com/netobserv/loki-client-go/pkg/backoff"
	"github.com/netobserv/loki-client-go/pkg/urlutil"
	"github.com/prometheus/common/model"
	"github.com/sirupsen/logrus"
)

var (
	keyReplacer = strings.NewReplacer("/", "_", ".", "_", "-", "_")
)

var log = logrus.WithField("component", "write.Loki")

type emitter interface {
	Handle(labels model.LabelSet, timestamp time.Time, record string) error
}

// Loki record writer
type Loki struct {
	lokiConfig     loki.Config
	apiConfig      api.WriteLoki
	timestampScale float64
	saneLabels     map[string]model.LabelName
	ignoreList     map[string]any
	client         emitter
	timeNow        func() time.Time
	exitChan       <-chan struct{}
	metrics        *metrics
	formatter      func(config.GenericMap) string
}

func buildLokiConfig(c *api.WriteLoki) (loki.Config, error) {
	batchWait, err := time.ParseDuration(c.BatchWait)
	if err != nil {
		return loki.Config{}, fmt.Errorf("failed in parsing BatchWait : %w", err)
	}

	timeout, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return loki.Config{}, fmt.Errorf("failed in parsing Timeout : %w", err)
	}

	minBackoff, err := time.ParseDuration(c.MinBackoff)
	if err != nil {
		return loki.Config{}, fmt.Errorf("failed in parsing MinBackoff : %w", err)
	}

	maxBackoff, err := time.ParseDuration(c.MaxBackoff)
	if err != nil {
		return loki.Config{}, fmt.Errorf("failed in parsing MaxBackoff : %w", err)
	}

	cfg := loki.Config{
		TenantID:  c.TenantID,
		BatchWait: batchWait,
		BatchSize: c.BatchSize,
		Timeout:   timeout,
		BackoffConfig: backoff.BackoffConfig{
			MinBackoff: minBackoff,
			MaxBackoff: maxBackoff,
			MaxRetries: c.MaxRetries,
		},
	}
	if c.ClientConfig != nil {
		cfg.Client = *c.ClientConfig
	}
	var clientURL urlutil.URLValue
	err = clientURL.Set(strings.TrimSuffix(c.URL, "/") + "/loki/api/v1/push")
	if err != nil {
		return cfg, fmt.Errorf("failed to parse client URL: %w", err)
	}
	cfg.URL = clientURL
	return cfg, nil
}

func (l *Loki) ProcessRecord(in config.GenericMap) error {
	labels, lines := l.splitLabelsLines(in)

	output := l.formatter(lines)
	timestamp := l.extractTimestamp(lines)

	err := l.client.Handle(labels, timestamp, output)
	if err == nil {
		l.metrics.recordsWritten.Inc()
	}
	return err
}

func (l *Loki) splitLabelsLines(in config.GenericMap) (model.LabelSet, config.GenericMap) {
	// Split the input GenericMap into one map for labels and another for lines / payload
	nLabels := len(l.apiConfig.StaticLabels) + len(l.saneLabels)
	labels := make(model.LabelSet, nLabels)
	lines := make(config.GenericMap, len(in))

	// Add static labels from config
	for k, v := range l.apiConfig.StaticLabels {
		labels[k] = v
	}

	for k, v := range in {
		if _, ignored := l.ignoreList[k]; ignored {
			continue
		}
		if sanitized, isLabel := l.saneLabels[k]; isLabel {
			lv := model.LabelValue(utils.ConvertToString(v))
			if !lv.IsValid() {
				log.WithFields(logrus.Fields{"key": k, "value": v}).Debug("Invalid label value. Ignoring it")
				continue
			}
			labels[sanitized] = lv
		} else {
			lines[k] = v
		}
	}

	return labels, lines
}

func (l *Loki) extractTimestamp(record map[string]interface{}) time.Time {
	if l.apiConfig.TimestampLabel == "" {
		return l.timeNow()
	}
	timestamp, ok := record[string(l.apiConfig.TimestampLabel)]
	if !ok {
		log.WithField("timestampLabel", l.apiConfig.TimestampLabel).
			Warnf("Timestamp label not found in record. Using local time")
		return l.timeNow()
	}
	ft, ok := getFloat64(timestamp)
	if !ok {
		log.WithField(string(l.apiConfig.TimestampLabel), timestamp).
			Warnf("Invalid timestamp found: float64 expected but got %T. Using local time", timestamp)
		return l.timeNow()
	}
	if ft == 0 {
		log.WithField("timestampLabel", l.apiConfig.TimestampLabel).
			Warnf("Empty timestamp in record. Using local time")
		return l.timeNow()
	}

	tsNanos := int64(ft * l.timestampScale)
	return time.Unix(tsNanos/int64(time.Second), tsNanos%int64(time.Second))
}

func getFloat64(timestamp interface{}) (ft float64, ok bool) {
	switch i := timestamp.(type) {
	case float64:
		return i, true
	case float32:
		return float64(i), true
	case int64:
		return float64(i), true
	case int32:
		return float64(i), true
	case uint64:
		return float64(i), true
	case uint32:
		return float64(i), true
	case int:
		return float64(i), true
	default:
		log.Warnf("Type %T is not implemented for float64 conversion\n", i)
		return math.NaN(), false
	}
}

// Write writes a flow before being stored
func (l *Loki) Write(entry config.GenericMap) {
	log.Tracef("writing entry: %#v", entry)
	err := l.ProcessRecord(entry)
	if err != nil {
		log.WithError(err).Warn("can't write into loki")
	}
}

// NewWriteLoki creates a Loki writer from configuration
func NewWriteLoki(opMetrics *operational.Metrics, params config.StageParam) (*Loki, error) {
	log.Debugf("entering NewWriteLoki")
	lokiConfigIn := api.WriteLoki{}
	if params.Write != nil && params.Write.Loki != nil {
		lokiConfigIn = *params.Write.Loki
	}
	// need to combine defaults with parameters that are provided in the config yaml file
	lokiConfigIn.SetDefaults()

	if err := lokiConfigIn.Validate(); err != nil {
		return nil, fmt.Errorf("the provided config is not valid: %w", err)
	}

	lokiConfig, buildconfigErr := buildLokiConfig(&lokiConfigIn)
	if buildconfigErr != nil {
		return nil, buildconfigErr
	}
	client, newWithLoggerErr := loki.NewWithLogger(lokiConfig, logAdapter.NewLogger(log.WithField("module", "export/loki")))
	if newWithLoggerErr != nil {
		return nil, newWithLoggerErr
	}

	timestampScale, err := time.ParseDuration(lokiConfigIn.TimestampScale)
	if err != nil {
		return nil, fmt.Errorf("cannot parse TimestampScale: %w", err)
	}

	// Sanitize label keys
	saneLabels := make(map[string]model.LabelName, len(lokiConfigIn.Labels))
	for _, label := range lokiConfigIn.Labels {
		sanitized := model.LabelName(keyReplacer.Replace(label))
		if sanitized.IsValidLegacy() {
			saneLabels[label] = sanitized
		} else {
			log.WithFields(logrus.Fields{"key": label, "sanitized": sanitized}).
				Debug("Invalid label. Ignoring it")
		}
	}

	// Ignore list to map
	ignoreList := make(map[string]any, len(lokiConfigIn.IgnoreList))
	for _, label := range lokiConfigIn.IgnoreList {
		ignoreList[label] = nil
	}

	f := formatter(lokiConfigIn.Format, lokiConfigIn.Reorder)
	l := &Loki{
		lokiConfig:     lokiConfig,
		apiConfig:      lokiConfigIn,
		timestampScale: float64(timestampScale),
		saneLabels:     saneLabels,
		ignoreList:     ignoreList,
		client:         client,
		timeNow:        time.Now,
		exitChan:       pUtils.ExitChannel(),
		metrics:        newMetrics(opMetrics, params.Name),
		formatter:      f,
	}

	return l, nil
}
