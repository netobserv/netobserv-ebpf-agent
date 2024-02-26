package encode

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
)

type Predicate func(flow config.GenericMap) bool

var variableExtractor, _ = regexp.Compile(`\$\(([^\)]+)\)`)

type MetricInfo struct {
	api.MetricsItem
	FilterPredicates []Predicate
}

func Presence(filter api.MetricsFilter) Predicate {
	return func(flow config.GenericMap) bool {
		_, found := flow[filter.Key]
		return found
	}
}

func Absence(filter api.MetricsFilter) Predicate {
	return func(flow config.GenericMap) bool {
		_, found := flow[filter.Key]
		return !found
	}
}

func Equal(filter api.MetricsFilter) Predicate {
	varLookups := extractVarLookups(filter.Value)
	return func(flow config.GenericMap) bool {
		if val, found := flow[filter.Key]; found {
			sVal, ok := val.(string)
			if !ok {
				sVal = fmt.Sprint(val)
			}
			value := filter.Value
			if len(varLookups) > 0 {
				value = injectVars(flow, value, varLookups)
			}
			return sVal == value
		}
		return false
	}
}

func NotEqual(filter api.MetricsFilter) Predicate {
	pred := Equal(filter)
	return func(flow config.GenericMap) bool { return !pred(flow) }
}

func Regex(filter api.MetricsFilter) Predicate {
	r, _ := regexp.Compile(filter.Value)
	return func(flow config.GenericMap) bool {
		if val, found := flow[filter.Key]; found {
			sVal, ok := val.(string)
			if !ok {
				sVal = fmt.Sprint(val)
			}
			return r.MatchString(sVal)
		}
		return false
	}
}

func NotRegex(filter api.MetricsFilter) Predicate {
	pred := Regex(filter)
	return func(flow config.GenericMap) bool { return !pred(flow) }
}

func filterToPredicate(filter api.MetricsFilter) Predicate {
	switch filter.Type {
	case api.PromFilterEqual:
		return Equal(filter)
	case api.PromFilterNotEqual:
		return NotEqual(filter)
	case api.PromFilterPresence:
		return Presence(filter)
	case api.PromFilterAbsence:
		return Absence(filter)
	case api.PromFilterRegex:
		return Regex(filter)
	case api.PromFilterNotRegex:
		return NotRegex(filter)
	}
	// Default = Exact
	return Equal(filter)
}

func extractVarLookups(value string) [][]string {
	// Extract list of variables to lookup
	// E.g: filter "$(SrcAddr):$(SrcPort)" would return [SrcAddr,SrcPort]
	if len(value) > 0 {
		return variableExtractor.FindAllStringSubmatch(value, -1)
	}
	return nil
}

func injectVars(flow config.GenericMap, filterValue string, varLookups [][]string) string {
	injected := filterValue
	for _, matchGroup := range varLookups {
		var value string
		if rawVal, found := flow[matchGroup[1]]; found {
			if sVal, ok := rawVal.(string); ok {
				value = sVal
			} else {
				value = fmt.Sprint(rawVal)
			}
		}
		injected = strings.ReplaceAll(injected, matchGroup[0], value)
	}
	return injected
}

func CreateMetricInfo(def api.MetricsItem) *MetricInfo {
	mi := MetricInfo{
		MetricsItem: def,
	}
	for _, f := range def.Filters {
		mi.FilterPredicates = append(mi.FilterPredicates, filterToPredicate(f))
	}
	return &mi
}
