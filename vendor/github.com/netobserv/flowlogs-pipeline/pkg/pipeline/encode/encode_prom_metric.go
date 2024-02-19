package encode

import (
	"fmt"
	"regexp"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
)

type Predicate func(flow config.GenericMap) bool

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

func Exact(filter api.MetricsFilter) Predicate {
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

func regex(filter api.MetricsFilter) Predicate {
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

func filterToPredicate(filter api.MetricsFilter) Predicate {
	switch filter.Type {
	case api.PromFilterExact:
		return Exact(filter)
	case api.PromFilterPresence:
		return Presence(filter)
	case api.PromFilterAbsence:
		return Absence(filter)
	case api.PromFilterRegex:
		return regex(filter)
	}
	// Default = Exact
	return Exact(filter)
}

func CreateMetricInfo(def api.MetricsItem) *MetricInfo {
	mi := MetricInfo{
		MetricsItem: def,
	}
	for _, f := range def.GetFilters() {
		mi.FilterPredicates = append(mi.FilterPredicates, filterToPredicate(f))
	}
	return &mi
}
