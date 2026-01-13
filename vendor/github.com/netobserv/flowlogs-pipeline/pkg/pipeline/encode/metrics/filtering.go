package metrics

import "github.com/netobserv/flowlogs-pipeline/pkg/config"

func (p *Preprocessed) ApplyFilters(flow config.GenericMap, flatParts []config.GenericMap) (bool, []config.GenericMap) {
	filteredParts := flatParts
	// For a given key, all related filters are OR'ed
	for _, filtersPerKey := range p.filters {
		allFailed := true
		for _, filter := range filtersPerKey {
			passed, nfp := applySingleFilter(flow, &filter, filteredParts)
			if passed {
				allFailed = false
				filteredParts = nfp
				break
			}
		}
		if allFailed {
			return false, nil
		}
	}
	return true, filteredParts
}

func applySingleFilter(flow config.GenericMap, filter *preprocessedFilter, filteredParts []config.GenericMap) (bool, []config.GenericMap) {
	if filter.useFlat {
		filteredParts = filter.filterFlatParts(filteredParts)
		if len(filteredParts) == 0 {
			return false, nil
		}
	} else if !filter.predicate(flow) {
		return false, nil
	}
	return true, filteredParts
}

func (pf *preprocessedFilter) filterFlatParts(flatParts []config.GenericMap) []config.GenericMap {
	var filteredParts []config.GenericMap
	for _, part := range flatParts {
		if pf.predicate(part) {
			filteredParts = append(filteredParts, part)
		}
	}
	return filteredParts
}
