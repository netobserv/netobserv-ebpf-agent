package agent

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
)

type interfaceFilter struct {
	totalAllowed     int
	totalExcluded    int
	allowedRegexpes  []*regexp.Regexp
	allowedMatches   []string
	excludedRegexpes []*regexp.Regexp
	excludedMatches  []string
}

func initInterfaceFilter(allowed, excluded []string) (interfaceFilter, error) {
	var isRegexp = regexp.MustCompile("^/(.*)/$")

	itf := interfaceFilter{}
	for _, definition := range allowed {
		itf.totalAllowed++
		definition = strings.Trim(definition, " ")
		// the user defined a /regexp/ between slashes: compile and store it
		if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 0 {
			re, err := regexp.Compile(definition)
			if err != nil {
				return itf, fmt.Errorf("wrong interface regexp %q: %w", definition, err)
			}
			itf.allowedRegexpes = append(itf.allowedRegexpes, re)
		} else {
			// otherwise, store it as exact match definition
			itf.allowedMatches = append(itf.allowedMatches, definition)
		}
	}

	for _, definition := range excluded {
		itf.totalExcluded++
		definition = strings.Trim(definition, " ")
		// the user defined a /regexp/ between slashes: compile and store it
		if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 0 {
			re, err := regexp.Compile(definition)
			if err != nil {
				return itf, fmt.Errorf("wrong excluded interface regexp %q: %w", definition, err)
			}
			itf.excludedRegexpes = append(itf.excludedRegexpes, re)
		} else {
			// otherwise, store it as exact match definition
			itf.excludedMatches = append(itf.excludedMatches, definition)
		}
	}

	return itf, nil
}

func (itf *interfaceFilter) Allowed(name ifaces.Name) bool {
	// if the allowed list is empty, any interface is allowed except if it matches the exclusion list
	allowed := itf.totalAllowed == 0
	// otherwise, we check if it appears in the allowed list
	for
}

func getInterfaces(cfg *Config, interfaces func() ([]net.Interface, error)) (map[string]struct{}, error) {
	// get interfaces from configuration or acquire them from the system
	actual, err := interfaces()
	if err != nil {
		return nil, fmt.Errorf("can't get network interfaces: %w", err)
	}
	accepted := map[string]struct{}{}

	// Accept only defined interfaces, or all if the interfaces section is not defined
	if len(cfg.Interfaces) > 0 {
		for _, definition := range cfg.Interfaces {
			for _, iface := range actual {
				if m, err := isMatch(iface.Name, definition); err != nil {
					return nil, fmt.Errorf("wrong definition of interface: %w", err)
				} else if m {
					accepted[iface.Name] = struct{}{}
				}
			}
		}
	} else {
		for _, iface := range actual {
			accepted[iface.Name] = struct{}{}
		}
	}

	// exclude interfaces
	for _, definition := range cfg.ExcludeInterfaces {
		for iface := range accepted {
			if m, err := isMatch(iface, definition); err != nil {
				return nil, fmt.Errorf("wrong definition of excluded interfaces: %w", err)
			} else if m {
				delete(accepted, iface)
			}
		}
	}
	return accepted, nil
}

func isMatch(iface, definition string) (bool, error) {
	definition = strings.Trim(definition, " ")

	// the user defined a /regexp/ between slashes: check if matches
	if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 0 {
		m, err := regexp.MatchString(sm[1], iface)
		if err != nil {
			return false, fmt.Errorf("wrong pattern %s: %w", definition, err)
		}
		return m, nil
	}
	// the user defined a plain string: check exact match
	return iface == definition, nil
}
