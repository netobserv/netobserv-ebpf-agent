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
//
//nolint:cyclop
func (f *Filter) Transform(entry config.GenericMap) (config.GenericMap, bool) {
	tlog.Tracef("f = %v", f)
	outputEntry := entry.Copy()
	labels := make(map[string]string)
	for _, rule := range f.Rules {
		tlog.Tracef("rule = %v", rule)
		switch rule.Type {
		case api.RemoveField:
			delete(outputEntry, rule.RemoveField.Input)
		case api.RemoveEntryIfExists:
			if _, ok := entry[rule.RemoveEntryIfExists.Input]; ok {
				return nil, false
			}
		case api.RemoveEntryIfDoesntExist:
			if _, ok := entry[rule.RemoveEntryIfDoesntExist.Input]; !ok {
				return nil, false
			}
		case api.RemoveEntryIfEqual:
			if val, ok := entry[rule.RemoveEntryIfEqual.Input]; ok {
				if val == rule.RemoveEntryIfEqual.Value {
					return nil, false
				}
			}
		case api.RemoveEntryIfNotEqual:
			if val, ok := entry[rule.RemoveEntryIfNotEqual.Input]; ok {
				if val != rule.RemoveEntryIfNotEqual.Value {
					return nil, false
				}
			}
		case api.AddField:
			outputEntry[rule.AddField.Input] = rule.AddField.Value
		case api.AddFieldIfDoesntExist:
			if _, ok := entry[rule.AddFieldIfDoesntExist.Input]; !ok {
				outputEntry[rule.AddFieldIfDoesntExist.Input] = rule.AddFieldIfDoesntExist.Value
			}
		case api.AddRegExIf:
			matched, err := regexp.MatchString(rule.AddRegExIf.Parameters, fmt.Sprintf("%s", outputEntry[rule.AddRegExIf.Input]))
			if err != nil {
				continue
			}
			if matched {
				outputEntry[rule.AddRegExIf.Output] = outputEntry[rule.AddRegExIf.Input]
				outputEntry[rule.AddRegExIf.Output+"_Matched"] = true
			}
		case api.AddFieldIf:
			expressionString := fmt.Sprintf("val %s", rule.AddFieldIf.Parameters)
			expression, err := govaluate.NewEvaluableExpression(expressionString)
			if err != nil {
				log.Warningf("Can't evaluate AddIf rule: %+v expression: %v. err %v", rule, expressionString, err)
				continue
			}
			result, evaluateErr := expression.Evaluate(map[string]interface{}{"val": outputEntry[rule.AddFieldIf.Input]})
			if evaluateErr == nil && result.(bool) {
				if rule.AddFieldIf.Assignee != "" {
					outputEntry[rule.AddFieldIf.Output] = rule.AddFieldIf.Assignee
				} else {
					outputEntry[rule.AddFieldIf.Output] = outputEntry[rule.AddFieldIf.Input]
				}
				outputEntry[rule.AddFieldIf.Output+"_Evaluate"] = true
			}
		case api.AddLabel:
			labels[rule.AddLabel.Input], _ = utils.ConvertToString(rule.AddLabel.Value)
		case api.AddLabelIf:
			// TODO perhaps add a cache of previously evaluated expressions
			expressionString := fmt.Sprintf("val %s", rule.AddLabelIf.Parameters)
			expression, err := govaluate.NewEvaluableExpression(expressionString)
			if err != nil {
				log.Warningf("Can't evaluate AddLabelIf rule: %+v expression: %v. err %v", rule, expressionString, err)
				continue
			}
			result, evaluateErr := expression.Evaluate(map[string]interface{}{"val": outputEntry[rule.AddLabelIf.Input]})
			if evaluateErr == nil && result.(bool) {
				labels[rule.AddLabelIf.Output] = rule.AddLabelIf.Assignee
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
