package encode

import (
	"fmt"
	"regexp"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
)

type predicate func(flow config.GenericMap) bool

type metricInfo struct {
	api.PromMetricsItem
	filterPredicates []predicate
}

func presence(filter api.PromMetricsFilter) predicate {
	return func(flow config.GenericMap) bool {
		_, found := flow[filter.Key]
		return found
	}
}

func absence(filter api.PromMetricsFilter) predicate {
	return func(flow config.GenericMap) bool {
		_, found := flow[filter.Key]
		return !found
	}
}

func exact(filter api.PromMetricsFilter) predicate {
	return func(flow config.GenericMap) bool {
		if val, found := flow[filter.Key]; found {
			sVal, ok := val.(string)
			if !ok {
				sVal = fmt.Sprint(val)
			}
			return sVal == filter.Value
		}
		return false
	}
}

func regex(filter api.PromMetricsFilter) predicate {
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

func filterToPredicate(filter api.PromMetricsFilter) predicate {
	switch filter.Type {
	case api.PromFilterExact:
		return exact(filter)
	case api.PromFilterPresence:
		return presence(filter)
	case api.PromFilterAbsence:
		return absence(filter)
	case api.PromFilterRegex:
		return regex(filter)
	}
	// Default = exact
	return exact(filter)
}

func CreateMetricInfo(def api.PromMetricsItem) *metricInfo {
	mi := metricInfo{
		PromMetricsItem: def,
	}
	for _, f := range def.GetFilters() {
		mi.filterPredicates = append(mi.filterPredicates, filterToPredicate(f))
	}
	return &mi
}
