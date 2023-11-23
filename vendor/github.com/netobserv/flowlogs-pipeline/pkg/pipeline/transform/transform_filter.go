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

package transform

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils"
	"github.com/sirupsen/logrus"
)

var tlog = logrus.WithField("component", "transform.Filter")

type Filter struct {
	Rules []api.TransformFilterRule
}

// Transform transforms a flow
func (f *Filter) Transform(entry config.GenericMap) (config.GenericMap, bool) {
	tlog.Tracef("f = %v", f)
	outputEntry := entry.Copy()
	labels := make(map[string]string)
	for _, rule := range f.Rules {
		tlog.Tracef("rule = %v", rule)
		switch rule.Type {
		case api.TransformFilterOperationName("RemoveField"):
			delete(outputEntry, rule.Input)
		case api.TransformFilterOperationName("RemoveEntryIfExists"):
			if _, ok := entry[rule.Input]; ok {
				return nil, false
			}
		case api.TransformFilterOperationName("RemoveEntryIfDoesntExist"):
			if _, ok := entry[rule.Input]; !ok {
				return nil, false
			}
		case api.TransformFilterOperationName("RemoveEntryIfEqual"):
			if val, ok := entry[rule.Input]; ok {
				if val == rule.Value {
					return nil, false
				}
			}
		case api.TransformFilterOperationName("RemoveEntryIfNotEqual"):
			if val, ok := entry[rule.Input]; ok {
				if val != rule.Value {
					return nil, false
				}
			}
		case api.TransformFilterOperationName("AddField"):
			outputEntry[rule.Input] = rule.Value
		case api.TransformFilterOperationName("AddFieldIfDoesntExist"):
			if _, ok := entry[rule.Input]; !ok {
				outputEntry[rule.Input] = rule.Value
			}
		case api.TransformFilterOperationName("AddRegExIf"):
			matched, err := regexp.MatchString(rule.Parameters, fmt.Sprintf("%s", outputEntry[rule.Input]))
			if err != nil {
				continue
			}
			if matched {
				outputEntry[rule.Output] = outputEntry[rule.Input]
				outputEntry[rule.Output+"_Matched"] = true
			}
		case api.TransformFilterOperationName("AddFieldIf"):
			expressionString := fmt.Sprintf("val %s", rule.Parameters)
			expression, err := govaluate.NewEvaluableExpression(expressionString)
			if err != nil {
				log.Warningf("Can't evaluate AddIf rule: %+v expression: %v. err %v", rule, expressionString, err)
				continue
			}
			result, evaluateErr := expression.Evaluate(map[string]interface{}{"val": outputEntry[rule.Input]})
			if evaluateErr == nil && result.(bool) {
				if rule.Assignee != "" {
					outputEntry[rule.Output] = rule.Assignee
				} else {
					outputEntry[rule.Output] = outputEntry[rule.Input]
				}
				outputEntry[rule.Output+"_Evaluate"] = true
			}
		case api.TransformFilterOperationName("AddLabel"):
			labels[rule.Input], _ = utils.ConvertToString(rule.Value)
		case api.TransformFilterOperationName("AddLabelIf"):
			// TODO perhaps add a cache of previously evaluated expressions
			expressionString := fmt.Sprintf("val %s", rule.Parameters)
			expression, err := govaluate.NewEvaluableExpression(expressionString)
			if err != nil {
				log.Warningf("Can't evaluate AddLabelIf rule: %+v expression: %v. err %v", rule, expressionString, err)
				continue
			}
			result, evaluateErr := expression.Evaluate(map[string]interface{}{"val": outputEntry[rule.Input]})
			if evaluateErr == nil && result.(bool) {
				labels[rule.Output] = rule.Assignee
			}
		default:
			tlog.Panicf("unknown type %s for transform.Filter rule: %v", rule.Type, rule)
		}
	}
	// process accumulated labels into comma separated string
	if len(labels) > 0 {
		var sb strings.Builder
		for key, value := range labels {
			sb.WriteString(key)
			sb.WriteString("=")
			sb.WriteString(value)
			sb.WriteString(",")
		}
		// remove trailing comma
		labelsString := sb.String()
		labelsString = strings.TrimRight(labelsString, ",")
		outputEntry["labels"] = labelsString
	}
	return outputEntry, true
}

// NewTransformFilter create a new filter transform
func NewTransformFilter(params config.StageParam) (Transformer, error) {
	tlog.Debugf("entering NewTransformFilter")
	rules := []api.TransformFilterRule{}
	if params.Transform != nil && params.Transform.Filter != nil {
		rules = params.Transform.Filter.Rules
	}
	transformFilter := &Filter{
		Rules: rules,
	}
	return transformFilter, nil
}
