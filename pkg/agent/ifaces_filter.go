package agent

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
)

type interfaceFilter struct {
	totalAllowed     int
	allowedRegexpes  []*regexp.Regexp
	allowedMatches   []ifaces.Name
	excludedRegexpes []*regexp.Regexp
	excludedMatches  []ifaces.Name
}

func initInterfaceFilter(allowed, excluded []string) (interfaceFilter, error) {
	var isRegexp = regexp.MustCompile("^/(.*)/$")

	itf := interfaceFilter{}
	for _, definition := range allowed {
		itf.totalAllowed++
		definition = strings.Trim(definition, " ")
		// the user defined a /regexp/ between slashes: compile and store it
		if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 1 {
			re, err := regexp.Compile(sm[1])
			if err != nil {
				return itf, fmt.Errorf("wrong interface regexp %q: %w", definition, err)
			}
			itf.allowedRegexpes = append(itf.allowedRegexpes, re)
		} else {
			// otherwise, store it as exact match definition
			itf.allowedMatches = append(itf.allowedMatches, ifaces.Name(definition))
		}
	}

	for _, definition := range excluded {
		definition = strings.Trim(definition, " ")
		// the user defined a /regexp/ between slashes: compile and store it
		if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 1 {
			re, err := regexp.Compile(sm[1])
			if err != nil {
				return itf, fmt.Errorf("wrong excluded interface regexp %q: %w", definition, err)
			}
			itf.excludedRegexpes = append(itf.excludedRegexpes, re)
		} else {
			// otherwise, store it as exact match definition
			itf.excludedMatches = append(itf.excludedMatches, ifaces.Name(definition))
		}
	}

	return itf, nil
}

func (itf *interfaceFilter) Allowed(name ifaces.Name) bool {
	// if the allowed list is empty, any interface is allowed except if it matches the exclusion list
	allowed := itf.totalAllowed == 0
	// otherwise, we check if it appears in the allowed lists
	for i := 0; !allowed && i < len(itf.allowedMatches); i++ {
		allowed = allowed || name == itf.allowedMatches[i]
	}
	for i := 0; !allowed && i < len(itf.allowedRegexpes); i++ {
		allowed = allowed || itf.allowedRegexpes[i].MatchString(string(name))
	}
	if !allowed {
		return false
	}
	// if it's in the allowed list, we need still to check if it's in the exclusion lists
	for _, match := range itf.excludedMatches {
		if name == match {
			return false
		}
	}
	for _, re := range itf.excludedRegexpes {
		if re.MatchString(string(name)) {
			return false
		}
	}
	return true
}
